package com.test.pgp.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Tests for {@link OpenPGPApiCrypto}, including interop with the low-level classes. */
class OpenPGPApiCryptoTest {

    /**
     * A new array on every call: the API may wipe a passphrase array after using it (for example
     * {@code OpenPGPKeyGenerator.build(char[])} does), so a shared constant would be blanked for
     * later tests.
     */
    private static char[] password() {
        return "password".toCharArray();
    }

    @TempDir Path tempDir;

    private OpenPGPApiCrypto crypto;
    private Path plain;
    private OpenPGPCertificate receiverCert;
    private OpenPGPKey receiverKey;
    private OpenPGPCertificate senderCert;
    private OpenPGPKey senderKey;

    @BeforeEach
    void setUp() throws Exception {
        crypto = new OpenPGPApiCrypto();
        plain = resource("test.txt");
        receiverCert = crypto.readCertificate(resource("receiver.gpg.pub"));
        receiverKey = crypto.readKey(resource("receiver.gpg.prv"));
        senderCert = crypto.readCertificate(resource("sender.gpg.pub"));
        senderKey = crypto.readKey(resource("sender.gpg.prv"));
    }

    @ParameterizedTest(name = "armored={0}")
    @ValueSource(booleans = {false, true})
    void encryptAndDecrypt(boolean armored) throws Exception {
        Path enc = tempDir.resolve("enc");
        Path dec = tempDir.resolve("dec");

        crypto.encryptFile(plain, enc, receiverCert, null, null, armored);
        OpenPGPMessageInputStream.Result result =
                crypto.decryptFile(enc, dec, receiverKey, password(), null);

        assertSameContent(plain, dec);
        assertTrue(result.getSignatures().isEmpty());
        assertEquals("test.txt", result.getFilename());
    }

    @ParameterizedTest(name = "armored={0}")
    @ValueSource(booleans = {false, true})
    void encryptSignAndDecryptVerify(boolean armored) throws Exception {
        Path enc = tempDir.resolve("enc");
        Path dec = tempDir.resolve("dec");

        crypto.encryptFile(plain, enc, receiverCert, senderKey, password(), armored);
        OpenPGPMessageInputStream.Result result =
                crypto.decryptFile(enc, dec, receiverKey, password(), senderCert);

        assertSameContent(plain, dec);
        assertEquals(1, result.getSignatures().size());
    }

    @Test
    void encryptsToTheEncryptionSubkey() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, null, null, false);

        OpenPGPMessageInputStream.Result result =
                crypto.decryptFile(enc, tempDir.resolve("dec"), receiverKey, password(), null);

        assertEquals(
                receiverCert.getEncryptionKeys().get(0).getKeyIdentifier(),
                result.getDecryptionKey().getKeyIdentifier());
    }

    @Test
    void verificationFailsForUnsignedMessage() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, null, null, false);

        assertThrows(
                Exception.class,
                () ->
                        crypto.decryptFile(
                                enc, tempDir.resolve("dec"), receiverKey, password(), senderCert));
    }

    @Test
    void verificationFailsForWrongSigner() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, senderKey, password(), false);

        // receiver's certificate did not sign the message
        assertThrows(
                Exception.class,
                () ->
                        crypto.decryptFile(
                                enc,
                                tempDir.resolve("dec"),
                                receiverKey,
                                password(),
                                receiverCert));
    }

    @Test
    void tamperedMessageIsRejected() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, senderKey, password(), false);
        byte[] bytes = Files.readAllBytes(enc);
        bytes[bytes.length - 1] ^= 1;
        Files.write(enc, bytes);

        assertThrows(
                Exception.class,
                () ->
                        crypto.decryptFile(
                                enc, tempDir.resolve("dec"), receiverKey, password(), senderCert));
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, null, null, false);

        assertThrows(
                Exception.class,
                () ->
                        crypto.decryptFile(
                                enc,
                                tempDir.resolve("dec"),
                                receiverKey,
                                "wrong".toCharArray(),
                                null));
    }

    /** Messages from the low-level BCPGPEncryptor can be read with the new API. */
    @Test
    void decryptsMessageFromLowLevelEncryptor() throws Exception {
        Path enc = tempDir.resolve("enc");
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setPublicKeyFilePath(resource("receiver.gpg.pub").toString());
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(resource("sender.gpg.prv").toString());
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile(plain.toString(), enc.toString());

        Path dec = tempDir.resolve("dec");
        crypto.decryptFile(enc, dec, receiverKey, password(), senderCert);

        assertSameContent(plain, dec);
    }

    /** Messages from the new API can be read with the low-level BCPGPDecryptor. */
    @Test
    void lowLevelDecryptorReadsMessageFromNewApi() throws Exception {
        Path enc = tempDir.resolve("enc");
        crypto.encryptFile(plain, enc, receiverCert, senderKey, password(), false);

        Path dec = tempDir.resolve("dec");
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(resource("receiver.gpg.prv").toString());
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(resource("sender.gpg.pub").toString());
        decryptor.decryptFile(enc.toString(), dec.toString());

        assertSameContent(plain, dec);
    }

    /**
     * legacy-test.txt.signed.asc was created in 2011 by GnuPG 1.4.9 with DSA-1024 / ElGamal-2048
     * keys and a SHA-1 signature, all of which the default policy rejects.
     */
    @Test
    void defaultPolicyRejectsLegacyGnuPGMessage() throws Exception {
        OpenPGPKey legacyKey = crypto.readKey(resource("legacy-receiver.gpg.prv"));

        assertThrows(
                PGPException.class,
                () ->
                        crypto.decryptFile(
                                resource("legacy-test.txt.signed.asc"),
                                tempDir.resolve("dec"),
                                legacyKey,
                                password(),
                                null));
    }

    @Test
    void relaxedPolicyDecryptsAndVerifiesLegacyGnuPGMessage() throws Exception {
        OpenPGPDefaultPolicy legacyPolicy =
                new OpenPGPDefaultPolicy()
                        .acceptPublicKeyAlgorithmWithMinimalStrength(
                                PublicKeyAlgorithmTags.DSA, 1024)
                        .acceptPublicKeyAlgorithmWithMinimalStrength(
                                PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, 2048)
                        // accept SHA-1 only for signatures made before SHA-1 was retired
                        .acceptDocumentSignatureHashAlgorithmUntil(
                                HashAlgorithmTags.SHA1,
                                Date.from(
                                        LocalDate.of(2013, 1, 1)
                                                .atStartOfDay(ZoneOffset.UTC)
                                                .toInstant()));
        OpenPGPApiCrypto legacyCrypto = new OpenPGPApiCrypto(legacyPolicy);
        Path dec = tempDir.resolve("dec");

        OpenPGPMessageInputStream.Result result =
                legacyCrypto.decryptFile(
                        resource("legacy-test.txt.signed.asc"),
                        dec,
                        legacyCrypto.readKey(resource("legacy-receiver.gpg.prv")),
                        password(),
                        legacyCrypto.readCertificate(resource("legacy-sender.gpg.pub")));

        assertEquals(
                "this is a test\nadd a second line\n",
                Files.readString(dec, StandardCharsets.UTF_8));
        assertEquals(1, result.getSignatures().size());
    }

    /** Keys generated in code: Ed25519 signing primary key with an X25519 encryption subkey. */
    @Test
    void roundTripWithGeneratedEd25519Keys() throws Exception {
        OpenPGPKey alice =
                crypto.getApi()
                        .generateKey()
                        .ed25519x25519Key("alice <alice@example.com>")
                        .build(password());
        OpenPGPKey bob =
                crypto.getApi()
                        .generateKey()
                        .ed25519x25519Key("bob <bob@example.com>")
                        .build(password());

        Path enc = tempDir.resolve("enc");
        Path dec = tempDir.resolve("dec");
        crypto.encryptFile(plain, enc, bob.toCertificate(), alice, password(), true);
        OpenPGPMessageInputStream.Result result =
                crypto.decryptFile(enc, dec, bob, password(), alice.toCertificate());

        assertSameContent(plain, dec);
        assertEquals(1, result.getSignatures().size());
    }

    private static Path resource(String name) throws URISyntaxException {
        return Path.of(OpenPGPApiCryptoTest.class.getResource("/" + name).toURI());
    }

    private static void assertSameContent(Path expected, Path actual) throws Exception {
        assertArrayEquals(Files.readAllBytes(expected), Files.readAllBytes(actual));
    }
}
