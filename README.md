# Tigera Secure EE Charm

This charm will deploy Tigera Secure Enterprise Edition (EE) as a background
service, and configure CNI for use with Tigera Secure EE, on any principal
charm that implements the [kubernetes-cni][] interface.

[kubernetes-cni]: https://github.com/juju-solutions/interface-kubernetes-cni

## Usage

The tigera-secure-ee charm is a [subordinate][]. This charm will require a
principal charm that implements the `kubernetes-cni` interface in order to
properly deploy.

[subordinate]: https://docs.jujucharms.com/2.4/en/authors-subordinate-applications

Documentation for how to use this with the Charmed Distribution of Kubernetes
can be found here: [Using Tigera Secure EE with CDK][]

[Using Tigera Secure EE with CDK]: https://ubuntu.com/kubernetes/docs/tigera-secure-ee

## Further information

- [Tigera Secure EE Homepage](https://www.tigera.io/tigera-secure-ee/)
