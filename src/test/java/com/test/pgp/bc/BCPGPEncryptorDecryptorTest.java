package com.test.pgp.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Round-trip tests for {@link BCPGPEncryptor} and {@link BCPGPDecryptor}.
 *
 * <p>Keys and input files live in src/test/resources (see README for how the keys were made);
 * everything the tests write goes to a temporary directory.
 */
class BCPGPEncryptorDecryptorTest {

    private static final String PASSWORD = "password";

    @TempDir Path tempDir;

    @ParameterizedTest(name = "armored={0}")
    @ValueSource(booleans = {false, true})
    void encryptAndDecrypt(boolean armored) throws Exception {
        Path encrypted = tempDir.resolve("test.txt.enc");
        Path decrypted = tempDir.resolve("test.txt.dec");

        BCPGPEncryptor encryptor = newEncryptor(armored);
        encryptor.encryptFile(resource("test.txt"), encrypted.toString());
        assertArmored(armored, encrypted);

        newDecryptor().decryptFile(encrypted.toString(), decrypted.toString());

        assertSameContent(Path.of(resource("test.txt")), decrypted);
    }

    @ParameterizedTest(name = "armored={0}")
    @ValueSource(booleans = {false, true})
    void encryptSignAndDecryptVerify(boolean armored) throws Exception {
        Path encrypted = tempDir.resolve("test.txt.signed.enc");
        Path decrypted = tempDir.resolve("test.txt.signed.dec");

        newSigningEncryptor(armored).encryptFile(resource("test.txt"), encrypted.toString());
        assertArmored(armored, encrypted);

        newVerifyingDecryptor().decryptFile(encrypted.toString(), decrypted.toString());

        assertSameContent(Path.of(resource("test.txt")), decrypted);
    }

    @Test
    void signedMessageCanBeDecryptedWithoutVerification() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.signed.enc");
        Path decrypted = tempDir.resolve("test.txt.dec");
        newSigningEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        newDecryptor().decryptFile(encrypted.toString(), decrypted.toString());

        assertSameContent(Path.of(resource("test.txt")), decrypted);
    }

    @Test
    void decryptToStream() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.enc");
        newEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        byte[] decrypted;
        try (InputStream in = Files.newInputStream(encrypted)) {
            decrypted = newDecryptor().decryptFile(in).readAllBytes();
        }

        assertArrayEquals(Files.readAllBytes(Path.of(resource("test.txt"))), decrypted);
    }

    @Test
    void encryptsToEncryptionSubkeyNotSigningPrimaryKey() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.enc");
        newEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        long recipientKeyId = recipientKeyId(encrypted);

        PGPPublicKey primaryKey =
                BCPGPUtils.readPublicKeyRingCollection(resource("receiver.gpg.pub"))
                        .getKeyRings()
                        .next()
                        .getPublicKey();
        assertNotEquals(
                primaryKey.getKeyID(),
                recipientKeyId,
                "message must not be encrypted to the signing-only primary key");
        assertEquals(
                recipientKeyId,
                BCPGPUtils.readPublicKey(resource("receiver.gpg.pub")).getKeyID(),
                "message must be encrypted to the key readPublicKey selects");
    }

    @Test
    void verificationFailsForUnsignedMessage() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.enc");
        newEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        PGPException e =
                assertThrows(
                        PGPException.class,
                        () ->
                                newVerifyingDecryptor()
                                        .decryptFile(
                                                encrypted.toString(),
                                                tempDir.resolve("out").toString()));
        assertTrue(e.getMessage().contains("not signed"), e.getMessage());
    }

    @Test
    void verificationFailsForUnknownSigner() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.signed.enc");
        newSigningEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        BCPGPDecryptor decryptor = newVerifyingDecryptor();
        decryptor.setSigningPublicKeyFilePath(resource("legacy-sender.gpg.pub"));

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        decryptor.decryptFile(
                                encrypted.toString(), tempDir.resolve("out").toString()));
    }

    @Test
    void tamperedMessageIsRejected() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.signed.enc");
        newSigningEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        // Flipping the last byte changes only the last byte of the integrity (MDC) hash.
        byte[] bytes = Files.readAllBytes(encrypted);
        bytes[bytes.length - 1] ^= 1;
        Path tampered = tempDir.resolve("tampered.enc");
        Files.write(tampered, bytes);

        assertThrows(
                PGPException.class,
                () ->
                        newVerifyingDecryptor()
                                .decryptFile(
                                        tampered.toString(), tempDir.resolve("out").toString()));
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        Path encrypted = tempDir.resolve("test.txt.enc");
        newEncryptor(false).encryptFile(resource("test.txt"), encrypted.toString());

        BCPGPDecryptor decryptor = newDecryptor();
        decryptor.setPassword("wrong password");

        assertThrows(
                PGPException.class,
                () ->
                        decryptor.decryptFile(
                                encrypted.toString(), tempDir.resolve("out").toString()));
    }

    /** legacy-test.txt.signed.asc was created in 2011 by GnuPG 1.4.9 with the legacy keys. */
    @Test
    void decryptAndVerifyLegacyGnuPGMessage() throws Exception {
        Path decrypted = tempDir.resolve("legacy.dec");

        BCPGPDecryptor decryptor = newLegacyDecryptor();
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(resource("legacy-sender.gpg.pub"));
        decryptor.decryptFile(resource("legacy-test.txt.signed.asc"), decrypted.toString());

        assertEquals(LEGACY_CONTENT, Files.readString(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void decryptLegacyGnuPGMessageWithoutVerification() throws Exception {
        Path decrypted = tempDir.resolve("legacy.dec");

        newLegacyDecryptor()
                .decryptFile(resource("legacy-test.txt.signed.asc"), decrypted.toString());

        assertEquals(LEGACY_CONTENT, Files.readString(decrypted, StandardCharsets.UTF_8));
    }

    private static final String LEGACY_CONTENT = "this is a test\nadd a second line\n";

    private static BCPGPEncryptor newEncryptor(boolean armored) throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(armored);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath(resource("receiver.gpg.pub"));
        return encryptor;
    }

    private static BCPGPEncryptor newSigningEncryptor(boolean armored) throws Exception {
        BCPGPEncryptor encryptor = newEncryptor(armored);
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(resource("sender.gpg.prv"));
        encryptor.setSigningPrivateKeyPassword(PASSWORD);
        return encryptor;
    }

    private static BCPGPDecryptor newDecryptor() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(resource("receiver.gpg.prv"));
        decryptor.setPassword(PASSWORD);
        return decryptor;
    }

    private static BCPGPDecryptor newVerifyingDecryptor() throws Exception {
        BCPGPDecryptor decryptor = newDecryptor();
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(resource("sender.gpg.pub"));
        return decryptor;
    }

    private static BCPGPDecryptor newLegacyDecryptor() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(resource("legacy-receiver.gpg.prv"));
        decryptor.setPassword(PASSWORD);
        return decryptor;
    }

    private static String resource(String name) throws URISyntaxException {
        return Path.of(BCPGPEncryptorDecryptorTest.class.getResource("/" + name).toURI())
                .toString();
    }

    private static long recipientKeyId(Path encrypted) throws Exception {
        try (InputStream in = PGPUtil.getDecoderStream(Files.newInputStream(encrypted))) {
            PGPEncryptedDataList enc =
                    (PGPEncryptedDataList) new JcaPGPObjectFactory(in).nextObject();
            return ((PGPPublicKeyEncryptedData) enc.get(0)).getKeyIdentifier().getKeyId();
        }
    }

    private static void assertArmored(boolean armored, Path file) throws Exception {
        String start = new String(Files.readAllBytes(file), 0, 27, StandardCharsets.US_ASCII);
        assertEquals(armored, start.equals("-----BEGIN PGP MESSAGE-----"), start);
    }

    private static void assertSameContent(Path expected, Path actual) throws Exception {
        assertArrayEquals(Files.readAllBytes(expected), Files.readAllBytes(actual));
    }
}
