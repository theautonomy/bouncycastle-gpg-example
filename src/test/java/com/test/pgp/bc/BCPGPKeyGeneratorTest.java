package com.test.pgp.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Generates key pairs with {@link BCPGPKeyGenerator} and checks that {@link BCPGPEncryptor} and
 * {@link BCPGPDecryptor} can use them. Key generation is slow, so the keys are made once.
 */
class BCPGPKeyGeneratorTest {

    private static final String PASSWORD = "secret";
    private static final byte[] CONTENT =
            "hello, generated keys\n".getBytes(StandardCharsets.UTF_8);

    @TempDir static Path keyDir;
    @TempDir Path tempDir;

    @BeforeAll
    static void generateKeys() throws Exception {
        // binary receiver key, armored sender key, so both formats get read back
        generate("Receiver <receiver@example.com>", false, "receiver");
        generate("Sender <sender@example.com>", true, "sender");
    }

    @Test
    void armoredKeysHaveArmorHeaders() throws Exception {
        assertTrue(readString("sender.pub").startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertTrue(readString("sender.prv").startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assertFalse(readString("receiver.pub").startsWith("-----BEGIN"));
    }

    @Test
    void publicKeyHasSigningPrimaryKeyAndEncryptionSubkey() throws Exception {
        PGPPublicKeyRing ring =
                BCPGPUtils.readPublicKeyRingCollection(key("receiver.pub")).getKeyRings().next();
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        PGPPublicKey primary = keys.next();
        PGPPublicKey subkey = keys.next();

        assertTrue(primary.isMasterKey());
        assertEquals("Receiver <receiver@example.com>", primary.getUserIDs().next());
        assertEquals(3072, primary.getBitStrength());
        assertEquals(3072, subkey.getBitStrength());
        assertNotEquals(primary.getKeyID(), subkey.getKeyID());
        assertEquals(
                subkey.getKeyID(),
                BCPGPUtils.readPublicKey(key("receiver.pub")).getKeyID(),
                "the subkey, not the primary key, must be chosen for encryption");
    }

    @ParameterizedTest(name = "armored={0}")
    @ValueSource(booleans = {false, true})
    void encryptSignAndDecryptVerify(boolean armored) throws Exception {
        Path input = tempDir.resolve("input.txt");
        Path encrypted = tempDir.resolve("input.txt.enc");
        Path decrypted = tempDir.resolve("input.txt.dec");
        Files.write(input, CONTENT);

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(armored);
        encryptor.setPublicKeyFilePath(key("receiver.pub"));
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(key("sender.prv"));
        encryptor.setSigningPrivateKeyPassword(PASSWORD);
        encryptor.encryptFile(input.toString(), encrypted.toString());

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(key("receiver.prv"));
        decryptor.setPassword(PASSWORD);
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(key("sender.pub"));
        decryptor.decryptFile(encrypted.toString(), decrypted.toString());

        assertArrayEquals(CONTENT, Files.readAllBytes(decrypted));
    }

    @Test
    void secretKeyIsProtectedByPassword() throws Exception {
        Path input = tempDir.resolve("input.txt");
        Path encrypted = tempDir.resolve("input.txt.enc");
        Files.write(input, CONTENT);

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setPublicKeyFilePath(key("receiver.pub"));
        encryptor.encryptFile(input.toString(), encrypted.toString());

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(key("receiver.prv"));
        decryptor.setPassword("wrong password");

        assertThrows(
                PGPException.class,
                () ->
                        decryptor.decryptFile(
                                encrypted.toString(), tempDir.resolve("out").toString()));
    }

    @Test
    void identityAndPasswordAreRequired() {
        BCPGPKeyGenerator generator = new BCPGPKeyGenerator();
        generator.setIdentity("No Password <nopass@example.com>");

        assertThrows(
                IllegalStateException.class,
                () ->
                        generator.generateKeys(
                                tempDir.resolve("k.pub").toString(),
                                tempDir.resolve("k.prv").toString()));
    }

    private static void generate(String identity, boolean armored, String name) throws Exception {
        BCPGPKeyGenerator generator = new BCPGPKeyGenerator();
        generator.setIdentity(identity);
        generator.setPassword(PASSWORD);
        generator.setArmored(armored);
        generator.generateKeys(key(name + ".pub"), key(name + ".prv"));
    }

    private static String key(String name) {
        return keyDir.resolve(name).toString();
    }

    private static String readString(String name) throws Exception {
        return Files.readString(keyDir.resolve(name), StandardCharsets.ISO_8859_1);
    }
}
