import hashlib
import os
import json
import gzip
import traceback

from conctl import getContainerRuntimeCtl
from base64 import b64decode, b64encode
from socket import gethostname
from subprocess import check_call, check_output, CalledProcessError

from charms.reactive import (when, when_not, when_any, is_state, set_state,
                             remove_state)
from charms.reactive import hook
from charms.reactive import endpoint_from_flag
from charms.reactive import data_changed
from charmhelpers.core import hookenv, unitdata
from charmhelpers.core.hookenv import log, status_set, resource_get
from charmhelpers.core.hookenv import DEBUG, ERROR
from charmhelpers.core.hookenv import unit_private_ip
from charmhelpers.core.templating import render
from charmhelpers.core.host import (arch, service, service_restart,
                                    service_running)

# TODO:
#   - Handle the 'stop' hook by stopping and uninstalling all the things.

os.environ['PATH'] += os.pathsep + os.path.join(os.sep, 'snap', 'bin')

try:
    CTL = getContainerRuntimeCtl()
    set_state('calico.ctl.ready')
except RuntimeError:
    log(traceback.format_exc())
    remove_state('calico.ctl.ready')

DEFAULT_REGISTRY = 'quay.io'
CALICOCTL_PATH = '/opt/calicoctl'
ETCD_KEY_PATH = os.path.join(CALICOCTL_PATH, 'etcd-key')
ETCD_CERT_PATH = os.path.join(CALICOCTL_PATH, 'etcd-cert')
ETCD_CA_PATH = os.path.join(CALICOCTL_PATH, 'etcd-ca')
CALICO_CIDR = '192.168.0.0/16'

db = unitdata.kv()


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('calico.binaries.installed')
    remove_state('calico.cni.configured')
    remove_state('calico.image.pulled')
    remove_state('calico.service.installed')
    remove_state('calico.npc.deployed')
    try:
        log('Deleting /etc/cni/net.d/10-calico.conf')
        os.remove('/etc/cni/net.d/10-calico.conf')
    except FileNotFoundError as e:
        log(e)


@when_not('calico.binaries.installed')
def install_calico_binaries():
    ''' Unpack the Calico binaries. '''
    # on intel, the resource is called 'calico'; other arches have a suffix
    architecture = arch()
    if architecture == 'amd64':
        resource_name = 'calico-cni'
    else:
        resource_name = 'calico-cni-{}'.format(architecture)

    try:
        archive = resource_get(resource_name)
    except Exception:
        message = 'Error fetching the calico resource.'
        log(message)
        status_set('blocked', message)
        return

    if not archive:
        message = 'Missing calico resource.'
        log(message)
        status_set('blocked', message)
        return

    filesize = os.stat(archive).st_size
    if filesize < 1000000:
        message = 'Incomplete calico resource'
        log(message)
        status_set('blocked', message)
        return

    status_set('maintenance', 'Unpacking calico resource.')

    charm_dir = os.getenv('CHARM_DIR')
    unpack_path = os.path.join(charm_dir, 'files', 'calico')
    os.makedirs(unpack_path, exist_ok=True)
    cmd = ['tar', 'xfz', archive, '-C', unpack_path]
    log(cmd)
    check_call(cmd)

    apps = [
        {'name': 'calico', 'path': '/opt/cni/bin'},
        {'name': 'calico-ipam', 'path': '/opt/cni/bin'},
    ]

    for app in apps:
        unpacked = os.path.join(unpack_path, app['name'])
        app_path = os.path.join(app['path'], app['name'])
        install = ['install', '-v', '-D', unpacked, app_path]
        check_call(install)

    set_state('calico.binaries.installed')


@when('calico.binaries.installed')
@when_not('etcd.connected')
def blocked_without_etcd():
    status_set('blocked', 'Waiting for relation to etcd')


@when('etcd.tls.available')
@when_not('calico.etcd-credentials.installed')
def install_etcd_credentials():
    etcd = endpoint_from_flag('etcd.available')
    etcd.save_client_credentials(ETCD_KEY_PATH, ETCD_CERT_PATH, ETCD_CA_PATH)
    # record initial data so that we can detect changes
    data_changed('calico.etcd.data', (etcd.get_connection_string(),
                                      etcd.get_client_credentials()))
    set_state('calico.etcd-credentials.installed')


@when('etcd.tls.available', 'calico.service.installed')
def check_etcd_updates():
    etcd = endpoint_from_flag('etcd.available')
    if data_changed('calico.etcd.data', (etcd.get_connection_string(),
                                         etcd.get_client_credentials())):
        etcd.save_client_credentials(ETCD_KEY_PATH,
                                     ETCD_CERT_PATH,
                                     ETCD_CA_PATH)
        remove_state('calico.service.installed')
        remove_state('calico.npc.deployed')


def get_bind_address():
    ''' Returns a non-fan bind address for the cni endpoint '''
    try:
        data = hookenv.network_get('cni')
    except NotImplementedError:
        # Juju < 2.1
        return unit_private_ip()

    if 'bind-addresses' not in data:
        # Juju < 2.3
        return unit_private_ip()

    for bind_address in data['bind-addresses']:
        if bind_address['interfacename'].startswith('fan-'):
            continue
        return bind_address['addresses'][0]['address']

    # If we made it here, we didn't find a non-fan CNI bind-address, which is
    # unexpected. Let's log a message and play it safe.
    log('Could not find a non-fan bind-address. Using private-address.')
    return unit_private_ip()


@when('calico.binaries.installed', 'etcd.available',
      'calico.etcd-credentials.installed')
@when_not('calico.service.installed')
def install_calico_service():
    ''' Install the calico-node systemd service. '''
    status_set('maintenance', 'Installing calico-node service.')
    etcd = endpoint_from_flag('etcd.available')
    service_path = os.path.join(os.sep, 'lib', 'systemd', 'system',
                                'calico-node.service')

    registry = hookenv.config('registry') or DEFAULT_REGISTRY
    image = hookenv.config('calico-node-image')
    uri = os.path.join(registry, image)

    render('calico-node.service', service_path, {
        'connection_string': etcd.get_connection_string(),
        'etcd_key_path': ETCD_KEY_PATH,
        'etcd_ca_path': ETCD_CA_PATH,
        'etcd_cert_path': ETCD_CERT_PATH,
        'nodename': gethostname(),
        # specify IP so calico doesn't grab a silly one from, say, lxdbr0
        'ip': get_bind_address(),
        'cnx_node_image': uri
    })
    service_restart('calico-node')
    service('enable', 'calico-node')
    set_state('calico.service.installed')


@when('calico.binaries.installed', 'etcd.available',
      'calico.etcd-credentials.installed')
@when_not('calico.pool.configured')
def configure_calico_pool():
    ''' Configure Calico IP pool. '''
    status_set('maintenance', 'Configuring Calico IP pool')
    config = hookenv.config()
    context = {
        'cidr': CALICO_CIDR,
        'ipip': config['ipip'],
        'nat_outgoing': 'true' if config['nat-outgoing'] else 'false',
    }
    render('pool.yaml', '/tmp/calico-pool.yaml', context)
    try:
        calicoctl('apply', '-f', '/tmp/calico-pool.yaml')
    except CalledProcessError:
        status_set('waiting', 'Waiting to retry calico pool configuration')
        return
    set_state('calico.pool.configured')


@when_any('config.changed.ipip', 'config.changed.nat-outgoing')
def reconfigure_calico_pool():
    ''' Reconfigure the Calico IP pool '''
    remove_state('calico.pool.configured')


@when('etcd.available', 'cni.is-worker')
@when_not('calico.cni.configured')
def configure_cni():
    ''' Configure Calico CNI. '''
    status_set('maintenance', 'Configuring Calico CNI')
    cni = endpoint_from_flag('cni.is-worker')
    etcd = endpoint_from_flag('etcd.available')
    os.makedirs('/etc/cni/net.d', exist_ok=True)
    cni_config = cni.get_config()
    context = {
        'connection_string': etcd.get_connection_string(),
        'etcd_key_path': ETCD_KEY_PATH,
        'etcd_cert_path': ETCD_CERT_PATH,
        'etcd_ca_path': ETCD_CA_PATH,
        'kubeconfig_path': cni_config['kubeconfig_path']
    }
    render('10-calico.conflist', '/etc/cni/net.d/10-calico.conflist', context)
    cni.set_config(cidr=CALICO_CIDR)
    set_state('calico.cni.configured')


@when('etcd.available', 'cni.is-master')
@when_not('calico.cni.configured')
def configure_master_cni():
    status_set('maintenance', 'Configuring Calico CNI')
    cni = endpoint_from_flag('cni.is-master')
    cni.set_config(cidr=CALICO_CIDR)
    set_state('calico.cni.configured')


@when('etcd.available', 'calico.cni.configured', 'calico.service.installed',
      'cni.is-worker', 'kube-api-endpoint.available')
@when_not('calico.npc.deployed')
def deploy_network_policy_controller():
    ''' Deploy the Calico network policy controller. '''
    status_set('maintenance', 'Applying registry credentials secret')

    # FIXME: We're just stealing a server key and cert from a random
    # worker. What should really go here?
    key_path = '/root/cdk/server.key'
    cert_path = '/root/cdk/server.crt'
    if not os.path.exists(key_path) or not os.path.exists(cert_path):
        msg = 'Waiting for cert generation'
        log(msg)
        hookenv.status_set('waiting', msg)
        return

    etcd = endpoint_from_flag('etcd.available')
    encoded_creds = hookenv.config('registry-credentials')
    registry = hookenv.config('registry')
    etcd_cert_hash = get_etcd_cert_hash()
    apiserver_ips = get_apiserver_ips()
    templates = []

    if encoded_creds:
        templates.append(('cnx-pull-secret.yaml', {
            'credentials': encoded_creds
        }))

    templates += [
        ('calico-config.yaml', {
            'etcd_endpoints': etcd.get_connection_string()
        }),
        ('calico-etcd-secrets.yaml', {
            'etcd_key': read_file_to_base64(ETCD_KEY_PATH),
            'etcd_cert': read_file_to_base64(ETCD_CERT_PATH),
            'etcd_ca': read_file_to_base64(ETCD_CA_PATH)
        }),
        ('calico-kube-controllers.yaml', {
            'registry': registry,
            'etcd_cert_hash': etcd_cert_hash
        }),
        ('cnx-manager-tls-secret.yaml', {
            'key': read_file_to_base64(key_path),
            'cert': read_file_to_base64(cert_path)
        }),
        ('cnx-etcd.yaml', {
            'registry': registry,
            'etcd_cert_hash': etcd_cert_hash
        }),
        ('cnx-policy.yaml', {})
    ]

    # elasticsearch-operator junk
    # elasticsearch-operator requires vm.max_map_count>=262144 on the host
    if hookenv.config('enable-elasticsearch-operator'):
        check_call(['sysctl', 'vm.max_map_count=262144'])
        templates += [
            ('elasticsearch-operator.yaml', {
                'registry': registry
            }),
            ('monitor-calico.yaml', {
                'apiserver_ips': json.dumps(apiserver_ips),
                'registry': registry
            })
        ]

    for template, context in templates:
        status_set('maintenance', 'Applying ' + template)
        dest = '/tmp/' + template
        render(template, dest, context)
        try:
            kubectl('apply', '-f', dest)
        except CalledProcessError:
            msg = 'Waiting to retry applying ' + template
            log(msg)
            status_set('waiting', msg)
            return

    license_key_b64 = hookenv.config('license-key')
    license_key = b64decode(license_key_b64).decode('utf-8')
    license_key_path = '/tmp/license-key.yaml'
    with open(license_key_path, 'w') as f:
        f.write(license_key)
    try:
        calicoctl('apply', '-f', license_key_path)
    except CalledProcessError:
        msg = 'Waiting to retry applying license-key'
        log(msg)
        status_set('waiting', msg)
        return

    db.set('tigera.apiserver_ips_used', apiserver_ips)
    set_state('calico.npc.deployed')


@when('calico.service.installed', 'calico.pool.configured',
      'calico.cni.configured')
@when_any('cni.is-master', 'calico.npc.deployed')
def ready():
    if not service_running('calico-node'):
        status_set('waiting', 'Waiting for service: calico-node')
    else:
        status_set('active', 'Calico is active')


@when('config.changed.registry-credentials')
def registry_credentials_changed():
    remove_state('calico.image.pulled')


@when('calico.ctl.ready')
@when_not('calico.image.pulled')
def pull_calicoctl_image():
    status_set('maintenance', 'Pulling calicoctl image')
    registry = hookenv.config('registry') or DEFAULT_REGISTRY
    encoded_creds = hookenv.config('registry-credentials')
    creds = b64decode(encoded_creds).decode('utf-8')
    if creds:
        creds = json.loads(creds)
    images = {
        os.path.join(registry, hookenv.config('calico-node-image')):
            resource_get('calico-node-image'),
        os.path.join(registry, hookenv.config('calicoctl-image')):
            resource_get('calicoctl-image')
    }

    for name, path in images.items():
        if not path or os.path.getsize(path) == 0:
            status_set('maintenance', 'Pulling {} image'.format(name))
            
            if not creds or not creds.get('auths') or \
                    registry not in creds.get('auths'):
                CTL.pull(
                    name,
                )
            else:
                auth = creds['auths'][registry]['auth']
                username, password = b64decode(auth).decode('utf-8').split(':')
                CTL.pull(
                    name,
                    username=username,
                    password=password
                )
        else:
            status_set('maintenance', 'Loading {} image'.format(name))
            unzipped = '/tmp/calico-node-image.tar'
            with gzip.open(path, 'rb') as f_in:
                with open(unzipped, 'wb') as f_out:
                    f_out.write(f_in.read())
            CTL.load(unzipped)

    set_state('calico.image.pulled')


@when('config.changed.registry')
def registry_changed():
    remove_state('calico.service.installed')
    remove_state('calico.npc.deployed')


@when('calico.npc.deployed', 'kube-api-endpoint.available')
def watch_for_api_endpoint_changes():
    apiserver_ips = get_apiserver_ips()
    old_apiserver_ips = db.get('tigera.apiserver_ips_used')
    if apiserver_ips != old_apiserver_ips:
        log('apiserver endpoints changed, preparing to reapply templates')
        remove_state('calico.npc.deployed')


def get_apiserver_ips():
    kube_api_endpoint = endpoint_from_flag('kube-api-endpoint.available')
    apiserver_ips = []
    for api_service in kube_api_endpoint.services():
        for host in api_service['hosts']:
            hostname = host['hostname']
            apiserver_ips.append(hostname)
    return apiserver_ips


def kubectl(*args):
    cmd = ['kubectl', '--kubeconfig=/root/.kube/config'] + list(args)
    return check_output(cmd)


def read_file_to_base64(path):
    with open(path, 'rb') as f:
        contents = f.read()
    contents = b64encode(contents).decode('utf-8')
    return contents


def calicoctl(*args):
    if not is_state('calioco.image.pulled'):
        pull_calicoctl_image()

    directories = [
        '/var/run/calico',
        '/var/lib/calico',
        '/run/containerd/plugins',
        '/var/log/calico'
    ]

    for d in directories:
        os.makedirs(d, exist_ok=True)

    etcd = endpoint_from_flag('etcd.available')
    registry = hookenv.config('registry') or DEFAULT_REGISTRY
    image = hookenv.config('calicoctl-image')
    uri = os.path.join(registry, image)

    run = CTL.run(
        net_host=True,
        mounts={
            CALICOCTL_PATH: CALICOCTL_PATH,
            '/tmp': '/tmp'
        },
        environment={
            'ETCD_ENDPOINTS': etcd.get_connection_string(),
            'ETCD_KEY_FILE': ETCD_KEY_PATH,
            'ETCD_CERT_FILE': ETCD_CERT_PATH,
            'ETCD_CA_CERT_FILE': ETCD_CA_PATH
        },
        name='calicoctl',
        image=uri,
        remove=True,
        command='calicoctl',
        args=args
    )

    if run.stderr:
        log(' '.join(run.stderr.decode()), ERROR)
        log(run.stderr.decode(), ERROR)

    elif run.stdout:
        log(' '.join(run.stderr.decode()), DEBUG)
        log(run.stdout.decode(), DEBUG)


def get_etcd_cert_hash():
    with open(ETCD_CERT_PATH, 'rb') as f:
        cert = f.read()
    cert_hash = hashlib.sha256(cert).hexdigest()
    return cert_hash
