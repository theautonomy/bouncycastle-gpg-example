package com.test.pgp.bc;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * Generates an OpenPGP key pair shaped like the one {@code gpg --gen-key} makes and the test keys
 * use: an RSA primary key for certifying and signing, plus an RSA subkey for encryption. The secret
 * keys are protected with the password (AES-256, iterated and salted SHA-256 S2K).
 *
 * <p>The public key file can be passed to {@link BCPGPEncryptor#setPublicKeyFilePath} and {@link
 * BCPGPDecryptor#setSigningPublicKeyFilePath}; the secret key file to {@link
 * BCPGPDecryptor#setPrivateKeyFilePath} and {@link BCPGPEncryptor#setSigningPrivateKeyFilePath}.
 * GnuPG can import both.
 */
public class BCPGPKeyGenerator {

    private String identity;
    private String password;
    private int keySize = 3072;
    private boolean isArmored;

    public String getIdentity() {
        return identity;
    }

    /** The user ID, conventionally {@code "Name <email@example.com>"}. */
    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public String getPassword() {
        return password;
    }

    /** The passphrase that protects the secret keys. */
    public void setPassword(String password) {
        this.password = password;
    }

    public int getKeySize() {
        return keySize;
    }

    /** RSA modulus size in bits for both keys. Defaults to 3072, GnuPG's default. */
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public boolean isArmored() {
        return isArmored;
    }

    public void setArmored(boolean isArmored) {
        this.isArmored = isArmored;
    }

    /** Generates a new key pair and writes the public and secret key rings to the given files. */
    public void generateKeys(String publicKeyFilePath, String secretKeyFilePath)
            throws IOException, PGPException, GeneralSecurityException {
        PGPKeyRingGenerator generator = createKeyRingGenerator();
        writeKeyRing(generator.generatePublicKeyRing(), publicKeyFilePath);
        writeKeyRing(generator.generateSecretKeyRing(), secretKeyFilePath);
    }

    private PGPKeyRingGenerator createKeyRingGenerator()
            throws PGPException, GeneralSecurityException {
        if (identity == null || password == null) {
            throw new IllegalStateException("Identity and password must be set.");
        }

        Date now = new Date();
        PGPKeyPair primaryKey = generateRsaKeyPair(now);
        PGPKeyPair encryptionKey = generateRsaKeyPair(now);

        // Self-signature on the user ID: what the primary key is for, and which algorithms we
        // prefer to receive. Senders such as BCPGPEncryptor read these preferences.
        PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        primarySubpackets.setPreferredSymmetricAlgorithms(
                false,
                new int[] {
                    SymmetricKeyAlgorithmTags.AES_256,
                    SymmetricKeyAlgorithmTags.AES_192,
                    SymmetricKeyAlgorithmTags.AES_128
                });
        primarySubpackets.setPreferredHashAlgorithms(
                false,
                new int[] {
                    HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
                });
        primarySubpackets.setPreferredCompressionAlgorithms(
                false,
                new int[] {
                    CompressionAlgorithmTags.ZLIB,
                    CompressionAlgorithmTags.ZIP,
                    CompressionAlgorithmTags.UNCOMPRESSED
                });
        primarySubpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Binding signature on the subkey: it is only for encryption.
        PGPSignatureSubpacketGenerator encryptionSubpackets = new PGPSignatureSubpacketGenerator();
        encryptionSubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPDigestCalculatorProvider digests =
                new JcaPGPDigestCalculatorProviderBuilder()
                        .setProvider(BCPGPUtils.PROVIDER)
                        .build();
        // Version 4 secret keys carry a SHA-1 checksum; the passphrase itself is hashed with
        // SHA-256.
        PGPDigestCalculator checksumCalculator = digests.get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator generator =
                new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION,
                        primaryKey,
                        identity,
                        checksumCalculator,
                        primarySubpackets.generate(),
                        null,
                        new JcaPGPContentSignerBuilder(
                                        primaryKey.getPublicKey().getAlgorithm(),
                                        HashAlgorithmTags.SHA256)
                                .setProvider(BCPGPUtils.PROVIDER),
                        new JcePBESecretKeyEncryptorBuilder(
                                        SymmetricKeyAlgorithmTags.AES_256,
                                        digests.get(HashAlgorithmTags.SHA256))
                                .setProvider(BCPGPUtils.PROVIDER)
                                .build(password.toCharArray()));
        generator.addSubKey(encryptionKey, encryptionSubpackets.generate(), null);
        return generator;
    }

    private PGPKeyPair generateRsaKeyPair(Date creationTime)
            throws PGPException, GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BCPGPUtils.PROVIDER);
        kpg.initialize(keySize);
        return new JcaPGPKeyPair(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.RSA_GENERAL,
                kpg.generateKeyPair(),
                creationTime);
    }

    private void writeKeyRing(PGPKeyRing keyRing, String filePath) throws IOException {
        // ArmoredOutputStream.close() writes the armor footer but leaves the file open, so the
        // file stream gets its own resource.
        try (OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(filePath));
                OutputStream out = isArmored ? new ArmoredOutputStream(fileOut) : fileOut) {
            keyRing.encode(out);
        }
    }
}
