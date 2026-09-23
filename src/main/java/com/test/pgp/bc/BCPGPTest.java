package com.test.pgp.bc;

public class BCPGPTest {

    public static void main(String[] args) throws Exception {
        encryptFile();
        decryptFile();
        encryptAndSignFile();
        decryptSignedFile();
        encryptAndSignFileArmored();
        decryptArmoredSignedFile();
        decryptSignedFile1();
        decryptSignedFileWithoutSignatureVerification();
    }

    public static void encryptFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.encryptFile("./test.txt", "./test.txt.enc");
    }

    public static void decryptFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.decryptFile("test.txt.enc", "test.txt.dec");
    }

    public static void encryptAndSignFile() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(false);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile("./test.txt", "./test.txt.signed.enc");
    }

    public static void decryptSignedFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");

        // this file is encrypted with weili's public key and signed using wahaha's private key
        decryptor.decryptFile("test.txt.signed.enc", "test.txt.signed.dec");
    }

    public static void encryptAndSignFileArmored() throws Exception {
        BCPGPEncryptor encryptor = new BCPGPEncryptor();
        encryptor.setArmored(true);
        encryptor.setCheckIntegrity(true);
        encryptor.setPublicKeyFilePath("./test.gpg.pub");
        encryptor.setSigning(true);
        encryptor.setSigningPrivateKeyFilePath("wahaha.gpg.prv");
        encryptor.setSigningPrivateKeyPassword("password");
        encryptor.encryptFile("./test.txt", "./test.txt.signed.enc.asc");
    }

    public static void decryptArmoredSignedFile() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");

        // same as decryptSignedFile, but the input is ASCII-armored
        decryptor.decryptFile("test.txt.signed.enc.asc", "test.txt.signed.armored.dec");
    }

    public static void decryptSignedFile1() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("legacy-test.gpg.prv");
        decryptor.setPassword("password");
        decryptor.setSigned(true);
        decryptor.setSigningPublicKeyFilePath("legacy-wahaha.gpg.pub");

        // this file was created in 2011 with the legacy keys: encrypted with weili's public key
        // and signed using wahaha's private key
        decryptor.decryptFile("legacy-test.txt.signed.asc", "test.txt.signed.dec1");
    }

    public static void decryptSignedFileWithoutSignatureVerification() throws Exception {
        BCPGPDecryptor decryptor = new BCPGPDecryptor();
        decryptor.setPrivateKeyFilePath("legacy-test.gpg.prv");
        decryptor.setPassword("password");

        // this file was created in 2011 with the legacy keys: encrypted with weili's public key
        // and signed using wahaha's private key
        decryptor.decryptFile("legacy-test.txt.signed.asc", "test.txt.signed.dec2");
    }
}
