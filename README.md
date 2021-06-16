[![Workflow Status](https://github.com/enarx/sevctl/workflows/test/badge.svg)](https://github.com/enarx/sevctl/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/sevctl.svg)](https://isitmaintained.com/project/enarx/sevctl "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/sevctl.svg)](https://isitmaintained.com/project/enarx/sevctl "Percentage of issues still open")
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
