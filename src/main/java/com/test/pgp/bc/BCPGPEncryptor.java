package com.test.pgp.bc;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

public class BCPGPEncryptor {

	private boolean isArmored;
	private boolean checkIntegrity;
	private String publicKeyFilePath;
	private PGPPublicKey publicKey;
	
	private String signingPrivateKeyFilePath;
	public String getSigningPrivateKeyFilePath() {
		return signingPrivateKeyFilePath;
	}

	public void setSigningPrivateKeyFilePath(String signingPrivateKeyFilePath) {
		this.signingPrivateKeyFilePath = signingPrivateKeyFilePath;
	}

	public boolean isSigned() {
		return isSigned;
	}

	public void setSigned(boolean isSigned) {
		this.isSigned = isSigned;
	}

	private boolean isSigned;
	
	private PGPEncryptedDataGenerator cPk;

	public String getPublicKeyFilePath() {
		return publicKeyFilePath;
	}

	public void setPublicKeyFilePath(String publicKeyFilePath)
			throws IOException, PGPException {
		this.publicKeyFilePath = publicKeyFilePath;
		publicKey = BCPGPUtils.readPublicKey(publicKeyFilePath);
	}

	public boolean isArmored() {
		return isArmored;
	}

	public void setArmored(boolean isArmored) {
		this.isArmored = isArmored;
	}

	public boolean isCheckIntegrity() {
		return checkIntegrity;
	}

	public void setCheckIntegrity(boolean checkIntegrity) {
		this.checkIntegrity = checkIntegrity;
	}

	public void encryptFile(String inputFileNamePath, String outputFileNamePath)
			throws IOException, NoSuchProviderException, PGPException {
		encryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
	}

	public void encryptFile(File inputFile, File outputFile)
			throws IOException, NoSuchProviderException, PGPException {
		if (cPk == null) {
			cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, checkIntegrity, new SecureRandom(), "BC");
			try {
				cPk.addMethod(publicKey);
			} catch (PGPException e) {
				throw new PGPException("Error when creating PGP encryptino data generator.");
			}
		}
		OutputStream out = new FileOutputStream(outputFile);
		if (isArmored) {
			out = new ArmoredOutputStream(out);
		}

		try {
			InputStream in = new FileInputStream(new File(signingPrivateKeyFilePath));
			PGPSecretKey pgpSec = BCPGPUtils.findSecretKey(in);
			PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(
					"password".toCharArray(), "BC");
			PGPSignatureGenerator sGen = new PGPSignatureGenerator(pgpSec
					.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");

			sGen.initSign(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

			Iterator it = pgpSec.getPublicKey().getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
				spGen.setSignerUserID(false, (String) it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			OutputStream os = comData.open(bOut);
			//sGen.generateOnePassVersion(false).encode(os);
			sGen.generateOnePassVersion(false).encode(bOut);
			PGPUtil.writeFileToLiteralData(os, PGPLiteralData.BINARY, inputFile);
			comData.close();
			byte[] bytes = bOut.toByteArray();
			OutputStream cOut = cPk.open(out, bytes.length);
			sGen.update(bytes);
			sGen.generate().encode(bOut);
			cOut.write(bytes);
			cOut.close();
			out.close();
		} catch (PGPException e) {
			System.err.println(e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

}