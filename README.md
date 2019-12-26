# dkey

dkey is a tool to generate deterministic app-specific keys from a master key.

App keys are organized hierarchically so that sub-trees can be shared (i.e.
master key at 'hardware/router1' can be securely transfered to that machine
to generate its sub-tree of runtime credentials locally).

## Instructions

1) Put user password in .dkey_pass or random 256bit key into .dkey_master at
the root directory (or optionally sub-directories to override key extension).

2) Create a .dkey_config:

```
hardware/router1:master
hardware/router1/gpg:gpg-rsa:name=foo,email=foo@bar.com
hardware/router1/ssh:ssh-rsa
hardware/router1/primary_network:wireguard
hardware/router1/secondary_network:wireguard
hardware/router1/sda2:luks
storage/bucket1:master
storage/bucket2:master
id/user1/ssh:ssh-rsa
id/user2/ssh:ssh-rsa
```

## Supported Apps

- [x] master/aes-256
- [x] wireguard (Curve25519)
- [x] ssh-rsa
- [ ] ssh-Curve25519
- [x] gpg-rsa
- [ ] gpg-Curve25519
- [x] luks (binary file unlock)
- [ ] iMX6 SRKs, fuses

	https://github.com/inversepath/usbarmory/blob/master/software/secure_boot/hab-pki/Makefile-pki

- [ ] ECP5 encryption key (AES-128)