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

### measurement build

Build measurement value from its component parts. The output is a
full measurement blob of measurement+nonce, similar to what qemu
and libvirt report.

```console
$ sevctl measurement build \
    --api-major 01 --api-minor 40 --build-id 40 \
    --policy 0x05 \
    --tik /path/to/VM_tik.bin \
    --launch-measure-blob /o0nzDKE5XgtVnUZWPhUea/WZYrTKLExR7KCwuMdbActvpWfXTFk21KMZIAAhQny \
    --firmware /usr/share/edk2/ovmf/OVMF.amdsev.fd \
    --kernel /path/to/kernel \
    --initrd /path/to/initrd \
    --cmdline "my kernel cmdline" \
    --vmsa-cpu0 /path/to/vmsa0.bin \
    --vmsa-cpu1 /path/to/vmsa1.bin \
    --num-cpus 4
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

### secret build

Generate secret header and payload binary content, and write to specified
output paths. Secrets are passed as `--secret UUID:FILENAME` pairs

```console
$ sevctl secret build \
    --tik /path/to/VM_tik.bin \
    --tek /path/to/VM_tik.bin \
    --launch-measure-blob /o0nzDKE5XgtVnUZWPhUea/WZYrTKLExR7KCwuMdbActvpWfXTFk21KMZIAAhQny \
    --secret 736869e5-84f0-4973-92ec-06879ce3da0b:/path/to/secret.txt \
    /path/to/secret_header.bin \
    /path/to/secret_payload.bin
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

### vmsa build

Build a VMSA binary blob and save to the specified filename.

```console
$ sevctl vmsa build NEW-VMSA0.bin --userspace qemu --family 25 --stepping 1 --model 1 --firmware /path/to/OVMF.amdsev.fd --cpu 0
```

### vmsa update

Update an existing VMSA binary file in place, with the passed options.

```console
$ sevctl vmsa build EXISTING-VMSA0.bin --userspace qemu --family 25 --stepping 1 --model 1 --firmware /path/to/OVMF.amdsev.fd --cpu 0
```

### vmsa show

Print an existing VMSA binary file as JSON

```console
$ sevctl vmsa show EXISTING-VMSA0.bin
```

License: Apache-2.0
