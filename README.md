## Introduction

This is an example of using Bouncy Castle's OpenPGP utility to encrypt 
and decrypt files.

This project is a refactory of the Bouncy Castle example which you can 
find [here](http://www.java2s.com/Open-Source/Java-Document/Security/Bouncy-Castle/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java.htm)

## Code snippet to encrypt a file without signing

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
		encryptor.setArmored(false);
		encryptor.setCheckIntegrity(true);
		encryptor.setPublicKeyFilePath("./test.gpg.pub");
		encryptor.encryptFile("./test.txt", "./test.txt.enc");
		
## Code snippet to decrypt a file without verifying signature;

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
	
## Code snippet to decrypt a file and verify signature;
		BCPGPDecryptor decryptor = new BCPGPDecryptor(); 
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");
		decryptor.setSigned(true);
		decryptor.setSigningPublicKeyFilePath("wahaha.gpg.pub");
		
		// this file is encrypted with weili's public key and signed using wahaha's private key
		decryptor.decryptFile("test.txt.signed.enc", "test.txt.signed.dec");


## Try it
This project contains a test pgp public and private key which are used for test
purpose so that you can try it out right away. You can run the following mvn command
from command line: 

        >mvn exec:java -Dexec.mainClass=com.test.pgp.bc.BCPGPTest

## Note
If you get error "java.security.InvalidKeyException: Illegal key size", you may need to install
the unrestricted policy files for the JVM you are using. See details [here](http://www.bouncycastle.org/wiki/display/JA1/Frequently+Asked+Questions)

 