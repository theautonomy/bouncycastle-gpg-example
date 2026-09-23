package com.test.pgp.bc;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class BCPGPEncryptor {

    private boolean isArmored;
    private boolean checkIntegrity = true;
    private String publicKeyFilePath;
    private PGPPublicKey publicKey;

    private boolean isSigning;
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

    public String getPublicKeyFilePath() {
        return publicKeyFilePath;
    }

    public void setPublicKeyFilePath(String publicKeyFilePath) throws IOException, PGPException {
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

    /**
     * Whether to add a modification detection code (MDC) to the encrypted data. Defaults to true;
     * modern GnuPG refuses to decrypt messages without one.
     */
    public void setCheckIntegrity(boolean checkIntegrity) {
        this.checkIntegrity = checkIntegrity;
    }

    public void encryptFile(String inputFileNamePath, String outputFileNamePath)
            throws IOException, PGPException {
        encryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
    }

    public void encryptFile(File inputFile, File outputFile) throws IOException, PGPException {
        if (publicKey == null) {
            throw new IllegalStateException("Public key file path is not set.");
        }

        PGPEncryptedDataGenerator pedg =
                new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                                .setWithIntegrityPacket(checkIntegrity)
                                .setSecureRandom(new SecureRandom())
                                .setProvider(BCPGPUtils.PROVIDER));
        pedg.addMethod(
                new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                        .setProvider(BCPGPUtils.PROVIDER));

        PGPSignatureGenerator sg = isSigning ? createSignatureGenerator() : null;

        // ArmoredOutputStream.close() writes the armor footer but does not close the stream it
        // wraps, so the file stream is closed separately (last).
        try (OutputStream fileOutStream =
                        new BufferedOutputStream(new FileOutputStream(outputFile));
                OutputStream out =
                        isArmored ? new ArmoredOutputStream(fileOutStream) : fileOutStream;
                OutputStream encryptedOutStream = pedg.open(out, new byte[1 << 16])) {
            PGPCompressedDataGenerator comData =
                    new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            try (OutputStream compressedOutStream = comData.open(encryptedOutStream)) {
                if (sg != null) {
                    sg.generateOnePassVersion(false).encode(compressedOutStream);
                }

                PGPLiteralDataGenerator lg = new PGPLiteralDataGenerator();
                try (InputStream in = new FileInputStream(inputFile);
                        OutputStream literalDataOutStream =
                                lg.open(
                                        compressedOutStream,
                                        PGPLiteralData.BINARY,
                                        inputFile.getName(),
                                        new Date(inputFile.lastModified()),
                                        new byte[1 << 16])) {
                    byte[] buf = new byte[1 << 16];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        literalDataOutStream.write(buf, 0, len);
                        if (sg != null) {
                            sg.update(buf, 0, len);
                        }
                    }
                }

                if (sg != null) {
                    sg.generate().encode(compressedOutStream);
                }
            }
        }
    }

    private PGPSignatureGenerator createSignatureGenerator() throws IOException, PGPException {
        if (signingPrivateKeyFilePath == null || signingPrivateKeyPassword == null) {
            throw new IllegalStateException(
                    "Signing private key file path or password is not set.");
        }

        PGPSecretKey secretKey;
        try (InputStream keyInputStream = new FileInputStream(signingPrivateKeyFilePath)) {
            secretKey = BCPGPUtils.findSecretKey(keyInputStream);
        }
        PGPPrivateKey privateKey =
                BCPGPUtils.extractPrivateKey(secretKey, signingPrivateKeyPassword.toCharArray());

        PGPPublicKey signingPublicKey = secretKey.getPublicKey();
        PGPSignatureGenerator sg =
                new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(
                                        signingPublicKey.getAlgorithm(), HashAlgorithmTags.SHA256)
                                .setProvider(BCPGPUtils.PROVIDER),
                        signingPublicKey);
        sg.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        Iterator<String> it = signingPublicKey.getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator ssg = new PGPSignatureSubpacketGenerator();
            ssg.addSignerUserID(false, it.next());
            sg.setHashedSubpackets(ssg.generate());
        }
        return sg;
    }
}
