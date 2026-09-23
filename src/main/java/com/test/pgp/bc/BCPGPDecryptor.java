package com.test.pgp.bc;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

public class BCPGPDecryptor {

    private String privateKeyFilePath;
    private String password;

    private boolean isSigned;
    private String signingPublicKeyFilePath;

    public boolean isSigned() {
        return isSigned;
    }

    public void setSigned(boolean isSigned) {
        this.isSigned = isSigned;
    }

    public String getSigningPublicKeyFilePath() {
        return signingPublicKeyFilePath;
    }

    public void setSigningPublicKeyFilePath(String signingPublicKeyFilePath) {
        this.signingPublicKeyFilePath = signingPublicKeyFilePath;
    }

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

    public void decryptFile(String inputFileNamePath, String outputFileNamePath)
            throws IOException, PGPException {
        decryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
    }

    public void decryptFile(File inputFile, File outputFile) throws IOException, PGPException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            decryptFile(in, out);
        }
    }

    /** Returns the decrypted content, buffered in memory. */
    public InputStream decryptFile(InputStream in) throws IOException, PGPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        decryptFile(in, out);
        return new ByteArrayInputStream(out.toByteArray());
    }

    /**
     * Decrypts {@code in} into {@code out}. Neither stream is closed. If verification fails, the
     * exception is thrown after the data has been written, so treat {@code out} as untrusted in
     * that case.
     */
    public void decryptFile(InputStream in, OutputStream out) throws IOException, PGPException {
        if (privateKeyFilePath == null || password == null) {
            throw new IllegalStateException("Private key file path or password is not set.");
        }

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(in));
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        PGPEncryptedDataList enc =
                o instanceof PGPEncryptedDataList
                        ? (PGPEncryptedDataList) o
                        : (PGPEncryptedDataList) pgpF.nextObject();

        //
        // find the secret key
        //
        PGPSecretKeyRingCollection pgpSec =
                BCPGPUtils.readSecretKeyRingCollection(privateKeyFilePath);
        char[] passwd = password.toCharArray();
        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        while (sKey == null && it.hasNext()) {
            PGPEncryptedData ed = it.next();
            if (ed instanceof PGPPublicKeyEncryptedData) {
                pbe = (PGPPublicKeyEncryptedData) ed;
                sKey = BCPGPUtils.findPrivateKey(pgpSec, pbe.getKeyIdentifier().getKeyId(), passwd);
            }
        }

        if (sKey == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }

        InputStream clear =
                pbe.getDataStream(
                        new JcePublicKeyDataDecryptorFactoryBuilder()
                                .setProvider(BCPGPUtils.PROVIDER)
                                .build(sKey));
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);
        Object message = pgpFact.nextObject();
        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
            message = pgpFact.nextObject();
        }

        PGPOnePassSignature ops = null;
        if (message instanceof PGPOnePassSignatureList) {
            if (isSigned) {
                ops = ((PGPOnePassSignatureList) message).get(0);
                PGPPublicKey signerPublicKey =
                        BCPGPUtils.readPublicKey(signingPublicKeyFilePath, ops.getKeyID());
                ops.init(
                        new JcaPGPContentVerifierBuilderProvider().setProvider(BCPGPUtils.PROVIDER),
                        signerPublicKey);
            }
            message = pgpFact.nextObject();
        }

        if (!(message instanceof PGPLiteralData)) {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }
        if (isSigned && ops == null) {
            throw new PGPException("Signature verification requested but message is not signed.");
        }

        try (InputStream literalIn = ((PGPLiteralData) message).getInputStream()) {
            byte[] buf = new byte[1 << 16];
            int len;
            while ((len = literalIn.read(buf)) > 0) {
                out.write(buf, 0, len);
                if (ops != null) {
                    ops.update(buf, 0, len);
                }
            }
        }
        out.flush();

        if (ops != null) {
            PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
            if (!ops.verify(p3.get(0))) {
                throw new PGPException("Signature verification failed!");
            }
        }

        // The integrity check can only run once the whole encrypted stream has been read.
        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            throw new PGPException("message failed integrity check");
        }
    }
}
