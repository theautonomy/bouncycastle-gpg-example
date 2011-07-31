## Introduction

This is an example of using Bouncy Castle's OpenPGP utility to encrypt 
and decrypt files.

This project is a refactory of the Bouncy Castle example which you can 
find [here](http://www.java2s.com/Open-Source/Java-Document/Security/Bouncy-Castle/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java.htm)

## Code snippet to encrypt a file

        BCPGPEncryptor encryptor = new BCPGPEncryptor();
		encryptor.setArmored(false);
		encryptor.setCheckIntegrity(true);
		encryptor.setPublicKeyFilePath("./test.gpg.pub");
		encryptor.encryptFile("./test.txt", "./test.txt.enc");
		
## Code snippet to decrypt a file

		BCPGPDecryptor decryptor = new BCPGPDecryptor(); 
		decryptor.setPrivateKeyFilePath("test.gpg.prv");
		decryptor.setPassword("password");
		decryptor.decryptFile("test.txt.enc", "test.txt.dec");

## This project contains a test pgp public and private key which are used for test
purpose so that you can try it out right away. You can run the following mvn command
from command line: 

        >mvn exec:java -Dexec.mainClass=com.test.pgp.bc.BCPGPTest

 