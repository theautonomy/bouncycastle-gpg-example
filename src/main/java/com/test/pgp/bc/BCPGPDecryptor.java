package com.test.pgp.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;

public class BCPGPDecryptor {
	
	private String privateKeyFilePath;
	private String password;
	
	public String getPrivateKeyFilePath() {
		return privateKeyFilePath;
	}

	public void setPrivateKeyFilePath(String privateKeyFilePath) {
		this.privateKeyFilePath = privateKeyFilePath;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	public void decryptFile(String inputFileNamePath, String outputFileNamePath) throws Exception {
		decryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
		
	}

	public void decryptFile(File inputFile, File outputFile) throws Exception {
		InputStream in = new FileInputStream(inputFile);
		InputStream keyIn = new FileInputStream(new File(privateKeyFilePath));
		char[] passwd = password.toCharArray();
		in = PGPUtil.getDecoderStream(in);

		try {
			PGPObjectFactory pgpF = new PGPObjectFactory(in);
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			//
			// the first object might be a PGP marker packet.
			//
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			//
			// find the secret key
			//
			Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			while (sKey == null && it.hasNext()) {
				pbe = it.next();
				sKey = BCPGPUtils.findSecretKey(keyIn, pbe.getKeyID(), passwd);
			}

			if (sKey == null) {
				throw new IllegalArgumentException( "secret key for message not found.");
			}

			InputStream clear = pbe.getDataStream(sKey, "BC");
			PGPObjectFactory plainFact = new PGPObjectFactory(clear);
			Object message = plainFact.nextObject();
			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				PGPObjectFactory pgpFact = new PGPObjectFactory( cData.getDataStream());
				message = pgpFact.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				//FileOutputStream fOut = new FileOutputStream(ld.getFileName());
				FileOutputStream fOut = new FileOutputStream(outputFile);
				InputStream unc = ld.getInputStream();
				int ch;
				while ((ch = unc.read()) >= 0) {
					fOut.write(ch);
				}
			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException(
						"encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException(
						"message is not a simple encrypted file - type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					throw new PGPException("message failed integrity check");
				} 
			}
		} catch (PGPException e) {
			System.err.println(e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		}
	}
	
}