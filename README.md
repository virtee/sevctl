[![Workflow Status](https://github.com/virtee/sevctl/workflows/test/badge.svg)](https://github.com/virtee/sevctl/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/virtee/sevctl.svg)](https://isitmaintained.com/project/virtee/sevctl "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/virtee/sevctl.svg)](https://isitmaintained.com/project/virtee/sevctl "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# sevctl

`sevctl` is a command line utility for managing the AMD Secure Encrypted Virtualization (SEV) platform.
It currently supports the entire management API for the Naples generation of processors.

## Usage

### help

Every `sevctl` (sub)command comes with a quick `--help` option for a reference on its use. For example:

```console
$ sevctl --help
```

or

```console
$ sevctl show --help
```

### export

Exports the SEV certificate chain to the provided file path.

```console
$ sevctl export /path/to/where/you/want/the-certificate
```

### generate

Generates a new (self-signed) OCA certificate and key.

```console
$ sevctl generate ~/my-cert ~/my-key
```

### ok

Probes processor, sysfs, and KVM for AMD SEV, SEV-ES, and SEV-SNP related features on the host and emits the results.

```console
$ sevctl ok {sev, es, snp}   // Probes support for the generation specified.
$ sevctl ok                  // Probes support for the host hardware's generation.
```

### provision

Installs the operator-provided OCA certificate to take ownership of the platform.

```console
$ sevctl provision ~/owners-cert ~/owners-private-key
```

### reset

Resets the SEV platform. This will clear all persistent data managed by the platform.

```console
$ sevctl reset
```

### rotate

Rotates the Platform Diffie-Hellman (PDH).

```console
$ sevctl rotate
```

### session

Given a certificate chain file and 32-bit policy, generates base64-encoded GODH and launch session files; as
well as encoded (not base64) TIK and TEK files.

```console
$ sevctl session --name {name} {/pdh/cert/path} {policy}
```
### show

Describes the state of the SEV platform.

```console
$ sevctl show flags
```

```console
$ sevctl show guests
```

### verify

Verifies the full SEV/CA certificate chain. File paths to these certificates can be supplied as
command line arguments if they are stored on the local filesystem. If they are not supplied, the
well-known public components will be downloaded from their remote locations.

```console
$ sevctl verify
```

License: Apache-2.0
