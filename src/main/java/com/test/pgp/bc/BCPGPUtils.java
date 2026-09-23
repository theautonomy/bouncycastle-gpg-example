package com.test.pgp.bc;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.util.Iterator;

import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public abstract class BCPGPUtils {

    /**
     * Provider instance handed directly to the JCA operator builders, so callers don't need to
     * register Bouncy Castle via {@code Security.addProvider}.
     */
    static final Provider PROVIDER = new BouncyCastleProvider();

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(String publicKeyFilePath)
            throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(new FileInputStream(publicKeyFilePath))) {
            return new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        }
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(String secretKeyFilePath)
            throws IOException, PGPException {
        try (InputStream in = new FileInputStream(secretKeyFilePath)) {
            return readSecretKeyRingCollection(in);
        }
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
    }

    /** Returns the first key in the file that is meant to be used for encryption. */
    public static PGPPublicKey readPublicKey(String publicKeyFilePath)
            throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = readPublicKeyRingCollection(publicKeyFilePath);

        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing ring = rIt.next();
            long primaryKeyId = ring.getPublicKey().getKeyID();
            Iterator<PGPPublicKey> kIt = ring.getPublicKeys();
            while (kIt.hasNext()) {
                PGPPublicKey k = kIt.next();
                if (isUsableForEncryption(k, primaryKeyId)) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * {@link PGPPublicKey#isEncryptionKey()} only checks that the algorithm can encrypt, which is
     * also true for an RSA signing key. When the key's self-signatures carry key flags, those
     * decide; older keys without key flags fall back to the algorithm check.
     */
    private static boolean isUsableForEncryption(PGPPublicKey key, long primaryKeyId) {
        if (!key.isEncryptionKey() || key.hasRevocation()) {
            return false;
        }

        boolean hasKeyFlags = false;
        Iterator<PGPSignature> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
            if (sig.getKeyID() != primaryKeyId
                    || hashed == null
                    || !hashed.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS)) {
                continue;
            }
            hasKeyFlags = true;
            if ((hashed.getKeyFlags() & (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0) {
                return true;
            }
        }
        return !hasKeyFlags;
    }

    /** Returns the key with the given key ID. */
    public static PGPPublicKey readPublicKey(String publicKeyFilePath, long keyId)
            throws IOException, PGPException {
        PGPPublicKey key = readPublicKeyRingCollection(publicKeyFilePath).getPublicKey(keyId);
        if (key == null) {
            throw new IllegalArgumentException(
                    "Can't find public key " + Long.toHexString(keyId) + " in key ring.");
        }
        return key;
    }

    public static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, char[] pass)
            throws PGPException {
        return secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider(PROVIDER).build(pass));
    }

    /** Returns the private key for the given key ID, or null if the collection doesn't have it. */
    public static PGPPrivateKey findPrivateKey(
            PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        return extractPrivateKey(pgpSecKey, pass);
    }

    public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException {
        return findPrivateKey(readSecretKeyRingCollection(keyIn), keyID, pass);
    }

    /**
     * Returns the first signing key in the key ring. In the real world you would probably want to
     * be a bit smarter about this.
     */
    public static PGPSecretKey findSecretKey(InputStream in) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = readSecretKeyRingCollection(in);

        Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings();
        while (rIt.hasNext()) {
            Iterator<PGPSecretKey> kIt = rIt.next().getSecretKeys();
            while (kIt.hasNext()) {
                PGPSecretKey k = kIt.next();
                if (k.isSigningKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }
}
