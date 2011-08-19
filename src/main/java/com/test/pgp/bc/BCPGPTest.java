package com.test.pgp.bc;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BCPGPTest {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		encryptFile();
		decryptFile();
		decryptSignedFile();
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
		public static void decryptSignedFile() throws Exception {
		BCPGPDecryptor decryptor = new BCPGPDecryptor(); 
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");
		decryptor.setSigned(true);
		decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");
		
		// this file is encrypted with weili's public key and signed using wahaha's private key
		decryptor.decryptFile("test.txt.signed.asc", "test.txt.signed.dec");
	}
	}