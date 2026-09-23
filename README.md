## Introduction

This is an example of using Bouncy Castle's OpenPGP utility to encrypt
and decrypt files.

This project is a refactory of the Bouncy Castle `KeyBasedLargeFileProcessor` example, which you can
find in the [bc-java repository](https://github.com/bcgit/bc-java/blob/main/misc/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java).

## Requirements

- Java 21 or later
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
        encryptor.setPublicKeyFilePath("./receiver.gpg.pub");
        encryptor.encryptFile("./test.txt", "./test.txt.enc");

## Code snippet to decrypt a file without verifying signature

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.decryptFile("test.txt.enc", "test.txt.dec");

## Code snippet to encrypt and sign a file

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./receiver.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath("sender.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile("./test.txt", "./test.txt.signed.enc");

## Code snippet to decrypt a file and verify signature

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("sender.gpg.pub");

        // this file is encrypted with the receiver public key and signed with the sender private key
        decryptor.decryptFile("test.txt.signed.enc", "test.txt.signed.dec");

## High-level API (`OpenPGPApiCrypto`)
`OpenPGPApiCrypto` does the same encrypt/sign and decrypt/verify work using Bouncy Castle's
high-level `org.bouncycastle.openpgp.api`. The API chooses the encryption subkey, negotiates
algorithms, and checks keys and signatures against a policy:

        OpenPGPApiCrypto crypto = new OpenPGPApiCrypto();
        crypto.encryptFile(Path.of("test.txt"), Path.of("test.txt.signed.enc"),
                crypto.readCertificate(Path.of("receiver.gpg.pub")),
                crypto.readKey(Path.of("sender.gpg.prv")), "password".toCharArray(), false);
        crypto.decryptFile(Path.of("test.txt.signed.enc"), Path.of("test.txt.signed.dec"),
                crypto.readKey(Path.of("receiver.gpg.prv")), "password".toCharArray(),
                crypto.readCertificate(Path.of("sender.gpg.pub")));

The default policy rejects weak keys and algorithms, such as the DSA-1024 / ElGamal keys and the
SHA-1 signature in `legacy-test.txt.signed.asc`. To read old data like that, pass a relaxed
`OpenPGPDefaultPolicy` to `new OpenPGPApiCrypto(policy)`; see
`OpenPGPApiCryptoTest.relaxedPolicyDecryptsAndVerifiesLegacyGnuPGMessage`.

## Try it
`src/main/java/com/test/pgp/bc/BCPGPTest.java` is a runnable example that goes through every
snippet above, in binary and ASCII-armored form, and also decrypts a message GnuPG 1.4.9 made in
2011. Run it from the project root; its output goes to `target/`:

        mvn clean compile exec:java

The unit tests in `src/test/java/com/test/pgp/bc/BCPGPEncryptorDecryptorTest.java` cover the
same scenarios plus failure cases (tampered message, wrong password, missing or unknown
signature). They write to a temporary directory that is deleted afterwards:

        mvn clean test

The keys and input files are in `src/test/resources`. The keys are for testing only; never
use them to protect real data.

| Files | Key | Passphrase |
|-------|-----|------------|
| `receiver.gpg.pub` / `receiver.gpg.prv` | receiver, RSA-3072: messages are encrypted to it and it decrypts them | `password` |
| `sender.gpg.pub` / `sender.gpg.prv` | sender, RSA-3072: signs messages | `password` |
| `legacy-receiver.gpg.prv` / `legacy-sender.gpg.pub` | the original 2011 DSA/ElGamal keys, kept only to decrypt and verify `legacy-test.txt.signed.asc` | `password` for the key that file uses |
| `test.txt` | the file the tests encrypt | |

## Creating the test keys
The `receiver` and `sender` keys were created with GnuPG 2.x. To create them again (or make
your own), run the following from `src/test/resources` in a bash shell (on Windows, Git
Bash works). A throwaway GnuPG home directory is used so your own keyring is not touched.

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
gen_key receiver receiver@example.com
gen_key sender sender@example.com

# export the keys in binary format; secret key exports need the passphrase
gpg --export receiver@example.com > receiver.gpg.pub
gpg --batch --pinentry-mode loopback --passphrase password \
    --export-secret-keys receiver@example.com > receiver.gpg.prv
gpg --export sender@example.com > sender.gpg.pub
gpg --batch --pinentry-mode loopback --passphrase password \
    --export-secret-keys sender@example.com > sender.gpg.prv

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
- `BCPGPUtils.readPublicKey` uses the first key in the file that is flagged for encryption,
  so keep one key ring per public key file.
