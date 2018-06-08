# ucert

ucert is a signature-chaining wrapper around usign using blob and blobmsg.
It's meant to be used for OpenWrt routers and uses libubox for most things, to allow dumping certificates in JSON format libjson-c and libblobmsg-json are used as well.

## a few words about security
ucert inherits all its cryptographic properties from the underlying **usign** implementation which as such may not have been meant to be used in such a way.
To maintain a high cryptographic standard, it is likely that further optimization of the signed payload format (reduce known-plaintext by normalization, add salts in case usign doesn't, ...) has to be carried out.
The parsers are inherited from libubox, and despite the extremely good reputation of the blob it must not be unmenetioned that libubox also most likely wasn't intended to be used for cryptographic purposes.
Yet it does provide the mechanisms needed (data-encapsulation, parsing, ...) in a way much more straight forward than any ASN.1 implementation ever could at a fraction of the source footprint.


## handling revokation
ucert generates a revoker certificate for each issued authorization certificate. Unlike X.509, the revokation mechanism is rather flat: It only allows keys present in pubkeydir (ie. /etc/opkg/keys) to revoke any other key. There are no means for delegation of revokation or anything the like.

When ucert is called with the `-R` command to process a chain of revokers, each of them is verified against the pubkeydir. Once validated, a dead symlink for the revoked key is created in /etc/opkg/keys.

Currently the signatures of the to-be-revoked keys are signed one-by-one -- if that turns out to be a scalability concern, revokation could easily be changed to operate with lists of to-be-revoked pubkeys. The advatage of the current implementation is that revokers can simple be appended and hence who ever takes care of the update or provisioning mechanism serving those revokers doesn't need to know anything about the internal affairs of ucert. They can simply use `cat`.

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

# on (OpenWrt) client
# get revokers periodically eg. via http and process them:
ucert -R -P /etc/opkg/keys -c all-revokers.ucrt
# verify message with ucert against pubkeys in /etc/opkg/keys
ucert -V -P /etc/opkg/keys -m message.bin -c message.bin.ucrt && echo message.bin verified successfully
```

