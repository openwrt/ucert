# ucert

ucert is a signature-chaining wrapper around usign using blob and blobmsg.
It's meant to be used for OpenWrt routers and uses libubox for most things, to allow dumping certificates in JSON format libjson-c and libblobmsg-json are used as well.

## a few words about security
ucert inherits all its cryptographic properties from the underlying usign implementation which as such wasn't meant to be used in such a way.
To maintain a high cryptographic standard, it is likely that further optimization of the signed payload format (reduce known-plaintext by normalization, add salts in case usign doesn't, ...) has to be carried out.

## usage
```shell
Usage: ucert <command> <options>
Commands:
  -A:			append signature (needs -c and -x)
  -D:			dump (needs -c)
  -I:			issue cert and revoker (needs -c and -p and -s)
  -R:			process revoker certificate (needs -c and -P)
  -V:			verify (needs -c and -p|-P, may have -m)
Options:
  -c <file>:		certificate file
  -m <file>:		message file (verify only)
  -p <file>:		public key file
  -P <path>:		public key directory (verify only)
  -q:			quiet (do not print verification result, use return code only)
  -s <file>:		secret key file (issue only)
  -x <file>:		signature file
```

### examples
```shell
# on airgap system
# create root keypair (which never leaves airgap)
usign -G -p capubkey -s caseckey
# create delegate keypair
usign -G -p pubkey -s seckey
# create ca-signed delegate cert (and revoker)
ucert -I -p pubkey -s caseckey -c newcert

# eg. on buildbot worker
# got newcert and seckey from airgap
# sign content
usign -S -m message.bin -s seckey -x message.bin.sig
# create cert for message
cp newcert message.bin.ucrt
ucert -A -c message.bin.ucrt -x message.bin.sig

# on client
ucert -V -P /etc/opkg/keys -m message.bin -c message.bin.ucrt && echo message.bin verified successfully
```
