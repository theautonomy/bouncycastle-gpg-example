package com.test.pgp.bc;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Runnable example of the encrypt/decrypt API: {@code mvn compile exec:java}, from the project
 * root. The keys and input files are in src/test/resources; output is written to target/. The same
 * scenarios are covered by the unit tests in BCPGPEncryptorDecryptorTest.
 */
public class BCPGPTest {

    private static final String RES = "src/test/resources/";
    private static final String OUT = "target/";

    public static void main(String[] args) throws Exception {
        new File(OUT).mkdirs();
        encryptFile();
        decryptFile();
        encryptAndSignFile();
        decryptSignedFile();
        encryptAndSignFileArmored();
        decryptArmoredSignedFile();
        decryptSignedFile1();
        decryptSignedFileWithoutSignatureVerification();
        generateKeysAndEncryptDecrypt();
    }

    public static void encryptFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath(RES + "receiver.gpg.pub");
        encryptor.encryptFile(RES + "test.txt", OUT + "test.txt.enc");
    }

    public static void decryptFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(RES + "receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.decryptFile(OUT + "test.txt.enc", OUT + "test.txt.dec");
    }

    public static void encryptAndSignFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath(RES + "receiver.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(RES + "sender.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile(RES + "test.txt", OUT + "test.txt.signed.enc");
    }

    public static void decryptSignedFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(RES + "receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(RES + "sender.gpg.pub");

        // this file is encrypted with the receiver public key and signed with the sender private
        // key
        decryptor.decryptFile(OUT + "test.txt.signed.enc", OUT + "test.txt.signed.dec");
    }

    public static void encryptAndSignFileArmored() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(true);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath(RES + "receiver.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(RES + "sender.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile(RES + "test.txt", OUT + "test.txt.signed.enc.asc");
    }

    public static void decryptArmoredSignedFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(RES + "receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(RES + "sender.gpg.pub");

        // same as decryptSignedFile, but the input is ASCII-armored
        decryptor.decryptFile(OUT + "test.txt.signed.enc.asc", OUT + "test.txt.signed.armored.dec");
    }

    public static void decryptSignedFile1() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(RES + "legacy-receiver.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(RES + "legacy-sender.gpg.pub");

        // this file was created in 2011: encrypted with the legacy-receiver public key
        // and signed with the legacy-sender private key
        decryptor.decryptFile(RES + "legacy-test.txt.signed.asc", OUT + "test.txt.signed.dec1");
    }

    public static void decryptSignedFileWithoutSignatureVerification() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(RES + "legacy-receiver.gpg.prv");
        decryptor.setPassword("password");

        // this file was created in 2011: encrypted with the legacy-receiver public key
        // and signed with the legacy-sender private key
        decryptor.decryptFile(RES + "legacy-test.txt.signed.asc", OUT + "test.txt.signed.dec2");
    }

    public static void generateKeysAndEncryptDecrypt() throws Exception {
        BCPGPKeyGenerator generator = new BCPGPKeyGenerator();
        generator.setIdentity("Generated <generated@example.com>");
        generator.setPassword("password");
        generator.setArmored(true);
        generator.generateKeys(OUT + "generated.gpg.pub.asc", OUT + "generated.gpg.prv.asc");
        printKey(OUT + "generated.gpg.pub.asc");
        printKey(OUT + "generated.gpg.prv.asc");

        // use the new key pair for both encryption and signing
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setPublicKeyFilePath(OUT + "generated.gpg.pub.asc");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath(OUT + "generated.gpg.prv.asc");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile(RES + "test.txt", OUT + "test.txt.generated.enc");

        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath(OUT + "generated.gpg.prv.asc");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath(OUT + "generated.gpg.pub.asc");
        decryptor.decryptFile(OUT + "test.txt.generated.enc", OUT + "test.txt.generated.dec");
    }

    private static void printKey(String filePath) throws Exception {
        System.out.println("Generated " + filePath + ":");
        System.out.println(Files.readString(Path.of(filePath)));
    }
}
