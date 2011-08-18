package com.test.pgp.bc;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BCPGPTest {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//encryptFile();
		decryptFile();
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
		//decryptor.decryptFile("test.txt.enc", "test.txt.dec");
		decryptor.decryptFile("test.signed.enc", "test.signed.dec");
	}
	}