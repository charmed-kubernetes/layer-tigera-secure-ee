import json
import os
from base64 import b64decode, b64encode
from socket import gethostname
from subprocess import check_call, check_output, CalledProcessError

from charms.reactive import when, when_not, when_any, set_state, remove_state
from charms.reactive import hook
from charms.reactive import endpoint_from_flag
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import log, status_set, resource_get
from charmhelpers.core.hookenv import unit_private_ip
from charmhelpers.core.host import service, service_start, service_running
from charmhelpers.core.templating import render

# TODO:
#   - Handle the 'stop' hook by stopping and uninstalling all the things.

os.environ['PATH'] += os.pathsep + os.path.join(os.sep, 'snap', 'bin')

CALICOCTL_PATH = '/opt/calicoctl'
ETCD_KEY_PATH = os.path.join(CALICOCTL_PATH, 'etcd-key')
ETCD_CERT_PATH = os.path.join(CALICOCTL_PATH, 'etcd-cert')
ETCD_CA_PATH = os.path.join(CALICOCTL_PATH, 'etcd-ca')
CALICO_CIDR = '192.168.0.0/16'


@hook('upgrade-charm')
def upgrade_charm():
    remove_state('calico.binaries.installed')
    remove_state('calico.cni.configured')
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
    if architecture == "amd64":
        resource_name = 'calico'
    else:
        resource_name = 'calico-{}'.format(architecture)

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
        {'name': 'calicoctl', 'path': CALICOCTL_PATH},
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
    set_state('calico.etcd-credentials.installed')


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
    render('calico-node.service', service_path, {
        'connection_string': etcd.get_connection_string(),
        'etcd_key_path': ETCD_KEY_PATH,
        'etcd_ca_path': ETCD_CA_PATH,
        'etcd_cert_path': ETCD_CERT_PATH,
        'nodename': gethostname(),
        # specify IP so calico doesn't grab a silly one from, say, lxdbr0
        'ip': get_bind_address(),
        'registry': hookenv.config('registry')
    })
    set_state('calico.service.installed')


@when('calico.service.installed', 'docker.available')
@when_not('calico.service.started')
def start_calico_service():
    ''' Start the calico systemd service. '''
    status_set('maintenance', 'Starting calico-node service.')
    service_start('calico-node')
    service('enable', 'calico-node')
    set_state('calico.service.started')


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


@when('etcd.available', 'calico.cni.configured',
      'calico.service.started', 'cni.is-worker')
@when_not('calico.npc.deployed')
def deploy_network_policy_controller():
    ''' Deploy the Calico network policy controller. '''
    status_set('maintenance', 'Applying registry credentials secret')

    etcd = endpoint_from_flag('etcd.available')
    encoded_creds = hookenv.config('registry-credentials')
    registry = hookenv.config('registry')
    templates = []

    if encoded_creds:
        templates.append(('cnx-pull-secret.yaml', {
            'credentials': encoded_creds
        }))

    templates += [
        ('policy-controller.yaml', {
            'connection_string': etcd.get_connection_string(),
            'etcd_key_path': ETCD_KEY_PATH,
            'etcd_cert_path': ETCD_CERT_PATH,
            'etcd_ca_path': ETCD_CA_PATH,
            'registry': registry
        }),
        ('calico-config.yaml', {
            'etcd_endpoints': etcd.get_connection_string()
        }),
        ('calico-etcd-secrets.yaml', {
            'etcd_key': read_file_to_base64(ETCD_KEY_PATH),
            'etcd_cert': read_file_to_base64(ETCD_CERT_PATH),
            'etcd_ca': read_file_to_base64(ETCD_CA_PATH)
        }),
        ('cnx-manager-tls-secret.yaml', {
            # FIXME: We're just stealing a server key and cert from a random
            # worker. What should really go here?
            'key': read_file_to_base64('/root/cdk/server.key'),
            'cert': read_file_to_base64('/root/cdk/server.crt')
        }),
        ('cnx-etcd.yaml', {
            'registry': registry
        }),
        ('cnx-policy.yaml', {})
    ]

    # elasticsearch-operator junk
    # elasticsearch-operator requires vm.max_map_count>=262144 on the host
    if hookenv.config('enable-elasticsearch-operator'):
        check_call(['sysctl', 'vm.max_map_count=262144'])
        try:
            output = kubectl('get', 'endpoints', 'kubernetes', '-o', 'json')
        except CalledProcessError:
            msg = 'Waiting to retry getting apiserver endpoints'
            log(msg)
            status_set('waiting', msg)
            return
        data = json.loads(output)
        apiserver_ips = []
        for subset in data['subsets']:
            for address in subset['addresses']:
                ip = address['ip']
                apiserver_ips.append(ip)
        templates += [
            ('elasticsearch-operator.yaml', {
                'registry': registry
            }),
            ('monitor-calico.yaml', {
                'apiserver_ips': json.dumps(apiserver_ips),
                'registry': registry
            }),
            ('kibana-dashboards.yaml', {
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

    set_state('calico.npc.deployed')


@when('calico.service.started', 'calico.pool.configured',
      'calico.cni.configured')
@when_any('cni.is-master', 'calico.npc.deployed')
def ready():
    if not service_running('calico-node'):
        status_set('waiting', 'Waiting for service: calico-node')
    else:
        status_set('active', 'Calico is active')


@when('config.changed.registry-credentials')
def registry_credentials_changed():
    status_set('maintenance', 'Applying registry credentials')
    encoded_creds = hookenv.config('registry-credentials')

    if not encoded_creds:
        hookenv.log('no registry-credentials, skipping docker config')
        return

    creds = b64decode(encoded_creds).decode('utf-8')
    config_dir = '/root/.docker'
    config_path = config_dir + '/config.json'
    os.makedirs(config_dir, exist_ok=True)
    with open(config_path, 'w') as f:
        f.write(creds)
    remove_state('calico.npc.deployed')


@when('config.changed.registry')
def registry_changed():
    remove_state('calico.service.installed')
    remove_state('calico.npc.deployed')


def kubectl(*args):
    cmd = ['kubectl', '--kubeconfig=/root/.kube/config'] + list(args)
    return check_output(cmd)


def read_file_to_base64(path):
    with open(path, 'rb') as f:
        contents = f.read()
    contents = b64encode(contents).decode('utf-8')
    return contents


def calicoctl(*args):
    etcd = endpoint_from_flag('etcd.available')
    env = os.environ.copy()
    env['ETCD_ENDPOINTS'] = etcd.get_connection_string()
    env['ETCD_KEY_FILE'] = ETCD_KEY_PATH
    env['ETCD_CERT_FILE'] = ETCD_CERT_PATH
    env['ETCD_CA_CERT_FILE'] = ETCD_CA_PATH
    cmd = ['/opt/calicoctl/calicoctl'] + list(args)
    return check_output(cmd, env=env)


def arch():
    '''Return the package architecture as a string.'''
    # Get the package architecture for this system.
    architecture = check_output(['dpkg', '--print-architecture']).rstrip()
    # Convert the binary result into a string.
    architecture = architecture.decode('utf-8')
    return architecture
