package com.test.pgp.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

public abstract class BCPGPUtils {

	public static PGPPublicKey readPublicKey(String publicKeyFilePath) throws IOException, PGPException {

		InputStream in = new FileInputStream(new File(publicKeyFilePath));

		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
		PGPPublicKey key = null;

		Iterator rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			boolean encryptionKeyFound = false;

			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException(
					"Can't find encryption key in key ring.");
		}

		return key;
	}

	public static PGPPublicKey readPublicKey(String publicKeyFilePath, long keyId) throws IOException, PGPException {

		InputStream in = new FileInputStream(new File(publicKeyFilePath));

		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
		PGPPublicKey key = null;

		Iterator rIt = pgpPub.getKeyRings();
		while (rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			boolean encryptionKeyFound = false;

			while (kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				long keyid = k.getKeyID();
				if (keyid == keyId) {
					key = k;
				}
				//if (k.isEncryptionKey()) {
				//	key = k;
				//}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException(
					"Can't find encryption key in key ring.");
		}

		return key;
	}
		public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID,
			char[] pass) throws IOException, PGPException,
			NoSuchProviderException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(keyIn));

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(pass, "BC");
	}
	
	public static PGPSecretKey findSecretKey(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection( in);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPSecretKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpSec.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();
            Iterator kIt = kRing.getSecretKeys();

            while (key == null && kIt.hasNext()) {
                PGPSecretKey k = (PGPSecretKey) kIt.next();

                if (k.isSigningKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException(
                    "Can't find signing key in key ring.");
        }
        return key;
    }
}
