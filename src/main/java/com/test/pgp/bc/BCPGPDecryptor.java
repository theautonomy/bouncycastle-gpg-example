package com.test.pgp.bc;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignatureList;
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
		decryptFile(new FileInputStream(inputFile), new FileOutputStream(
				outputFile));
	}

	public void decryptFile(InputStream in, OutputStream out) throws Exception {
		BufferedOutputStream bOut = new BufferedOutputStream(out);
		InputStream unc = decryptFile(in);
		int ch;
		while ((ch = unc.read()) >= 0) {
			bOut.write(ch);
		}
		bOut.close();

	}

	public InputStream decryptFile(InputStream in) throws Exception {
		InputStream is = null;
		InputStream keyIn = new FileInputStream(new File(privateKeyFilePath));
		char[] passwd = password.toCharArray();
		in = PGPUtil.getDecoderStream(in);

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
		PGPObjectFactory pgpFact = null; 
		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			pgpFact = new PGPObjectFactory(cData.getDataStream());
			message = pgpFact.nextObject();
		}

        PGPOnePassSignature ops = null; 
		if (message instanceof PGPOnePassSignatureList) {
			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)message; 
            ops = p1.get(0);
            PGPPublicKey signerPublicKey = BCPGPUtils.readPublicKey("wahaha.gpg.pub");
            //ops.initVerify(signerPublicKey, "BC");
            ops.initVerify(signerPublicKey, "BC");
			message = pgpFact.nextObject();
			
		}
		
		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;
			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					throw new PGPException("message failed integrity check");
				}
			}
			//return ld.getInputStream();
			is = ld.getInputStream();
			
			 PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

             if (ops.verify(p3.get(0))) {
                 System.out.println("signature verified.");
             } else {
                 System.out.println("signature verification failed.");
             }
		} 
		else {
			throw new PGPException(
					"message is not a simple encrypted file - type unknown.");
		}
		return is;
	}

}