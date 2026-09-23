## Introduction

This is an example of using Bouncy Castle's OpenPGP utility to encrypt
and decrypt files.

This project is a refactory of the Bouncy Castle `KeyBasedLargeFileProcessor` example, which you can
find in the [bc-java repository](https://github.com/bcgit/bc-java/blob/main/misc/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java).

## Requirements

- Java 17 or later
- Maven 3.6.3 or later
- Bouncy Castle 1.86 (`bcpg-jdk18on` / `bcprov-jdk18on`), pulled in by Maven

The Bouncy Castle provider is passed directly to the operator builders, so there is no need to
call `Security.addProvider(new BouncyCastleProvider())` before using these classes.

Encrypted files use AES-256 with an integrity check (MDC) enabled by default, and signatures use
SHA-256.

## Code snippet to encrypt a file without signing

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.encryptFile("./test.txt", "./test.txt.enc");

## Code snippet to decrypt a file without verifying signature

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.decryptFile("test.txt.enc", "test.txt.dec");

## Code snippet to encrypt and sign a file

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile("./test.txt", "./test.txt.signed.enc");

## Code snippet to decrypt a file and verify signature

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");

        // this file is encrypted with weili's public key and signed using wahaha's private key
        decryptor.decryptFile("test.txt.signed.enc", "test.txt.signed.dec");

## Try it
This project contains test pgp keys so that you can try it out right away. They are for
testing only; never use them to protect real data.

| Files | Key | Passphrase |
|-------|-----|------------|
| `test.gpg.pub` / `test.gpg.prv` | weili, RSA-3072, recipient | `password` |
| `wahaha.gpg.pub` / `wahaha.gpg.prv` | wahaha, RSA-3072, signer | `password` |
| `legacy-test.gpg.prv` / `legacy-wahaha.gpg.pub` | the original 2011 DSA/ElGamal keys, kept only to decrypt and verify `legacy-test.txt.signed.asc` | `password` for the key that file uses |

You can run the following mvn command from command line:

        mvn compile exec:java

Besides the binary output, the demo also writes an ASCII-armored encrypted and signed copy,
`test.txt.signed.enc.asc`, and decrypts it back to `test.txt.signed.armored.dec`.

To remove the generated files (`test.txt.enc`, `test.txt.dec`, `test.txt.signed.*` and
`target/`) afterwards, run:

        ./clean.sh

## Creating the test keys
The `test` and `wahaha` keys were created with GnuPG 2.x. To create them again (or make
your own), run the following from the project root in a bash shell (on Windows, Git Bash
works). A throwaway GnuPG home directory is used so your own keyring is not touched.

```bash
export GNUPGHOME=$(mktemp -d)
echo allow-loopback-pinentry > "$GNUPGHOME/gpg-agent.conf"

# generate a key pair: RSA-3072 signing primary key + RSA-3072 encryption subkey
gen_key() {
gpg --batch --pinentry-mode loopback --gen-key <<EOF
Key-Type: RSA
Key-Length: 3072
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 3072
Subkey-Usage: encrypt
Name-Real: $1
Name-Comment: test key
Name-Email: $2
Expire-Date: 0
Passphrase: password
%commit
EOF
}
gen_key weili weili@example.com
gen_key wahaha wahaha@example.com

# export the keys in binary format; secret key exports need the passphrase
gpg --export weili@example.com > test.gpg.pub
gpg --batch --pinentry-mode loopback --passphrase password \
    --export-secret-keys weili@example.com > test.gpg.prv
gpg --export wahaha@example.com > wahaha.gpg.pub
gpg --batch --pinentry-mode loopback --passphrase password \
    --export-secret-keys wahaha@example.com > wahaha.gpg.prv

# clean up the throwaway home directory
gpgconf --kill gpg-agent
rm -rf "$GNUPGHOME"
unset GNUPGHOME
```

Notes:
- `--pinentry-mode loopback` with `--passphrase` passes the passphrase on the command line,
  so gpg does not open a passphrase popup. This is fine for test keys; don't do it for real
  keys, because the passphrase ends up in your shell history.
- Add `--armor` to the export commands to get ASCII-armored keys. The code reads both
  formats.
- `BCPGPUtils.readPublicKey` uses the first encryption-capable key in the file, so keep one
  key ring per public key file.
