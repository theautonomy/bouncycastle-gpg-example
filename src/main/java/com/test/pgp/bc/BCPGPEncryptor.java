package com.test.pgp.bc;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
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
	private String signingPrivateKeyPassword;

	public String getSigningPrivateKeyPassword() {
		return signingPrivateKeyPassword;
	}

	public void setSigningPrivateKeyPassword(String signingPrivateKeyPassword) {
		this.signingPrivateKeyPassword = signingPrivateKeyPassword;
	}

	public String getSigningPrivateKeyFilePath() {
		return signingPrivateKeyFilePath;
	}

	public void setSigningPrivateKeyFilePath(String signingPrivateKeyFilePath) {
		this.signingPrivateKeyFilePath = signingPrivateKeyFilePath;
	}

	public boolean isSigning() {
		return isSigning;
	}

	public void setSigning(boolean isSigning) {
		this.isSigning = isSigning;
	}

	private boolean isSigning;

	private PGPEncryptedDataGenerator pedg;

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
		if (pedg == null) {
			pedg = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5,
					checkIntegrity, new SecureRandom(), "BC");
			
			try {
				pedg.addMethod(publicKey);
			} catch (PGPException e) {
				throw new PGPException(
						"Error when creating PGP encryptino data generator.");
			}
		}
		OutputStream fileOutStream = new FileOutputStream(outputFile);
		if (isArmored) {
			fileOutStream = new ArmoredOutputStream(fileOutStream);
		}

		OutputStream encryptdOutStream = pedg.open(fileOutStream, new byte[1 << 16]);
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator( PGPCompressedData.ZIP);
		OutputStream compressedOutStream = comData.open(encryptdOutStream);

		try {
			PGPSignatureGenerator sg = null;
			if (isSigning) {
				InputStream keyInputStream = new FileInputStream(new File( signingPrivateKeyFilePath));
				PGPSecretKey secretKey = BCPGPUtils.findSecretKey(keyInputStream);
				PGPPrivateKey privateKey = secretKey.extractPrivateKey( signingPrivateKeyPassword.toCharArray(), "BC");
				sg = new PGPSignatureGenerator(secretKey.getPublicKey() .getAlgorithm(), PGPUtil.SHA1, "BC");
				sg.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);
				Iterator it = secretKey.getPublicKey().getUserIDs();
				if (it.hasNext()) {
					PGPSignatureSubpacketGenerator ssg = new PGPSignatureSubpacketGenerator();
					ssg.setSignerUserID(false, (String) it.next());
					sg.setHashedSubpackets(ssg.generate());
				}
				sg.generateOnePassVersion(false).encode(compressedOutStream);
			}

			PGPLiteralDataGenerator lg= new PGPLiteralDataGenerator();
			OutputStream literalDataOutStream = lg.open(compressedOutStream, PGPLiteralData.BINARY, inputFile);

			byte[] bytes = IOUtils.toByteArray(new FileInputStream(inputFile));

			literalDataOutStream.write(bytes);
			if (isSigning) {
				sg.update(bytes);
			    sg.generate().encode(compressedOutStream);
			}
			literalDataOutStream.close();
			lg.close();
			compressedOutStream.close();
			comData.close();
			pedg.close();
			fileOutStream.close();
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