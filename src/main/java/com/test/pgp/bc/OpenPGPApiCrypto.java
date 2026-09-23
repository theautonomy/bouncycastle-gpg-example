package com.test.pgp.bc;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPApi;

/**
 * The same encrypt/sign and decrypt/verify operations as {@link BCPGPEncryptor} and {@link
 * BCPGPDecryptor}, written against Bouncy Castle's high-level {@code org.bouncycastle.openpgp.api}.
 *
 * <p>The API picks the recipient's encryption subkey, negotiates algorithms from the key's
 * preferences, and validates keys and signatures against a policy (expiry, revocation, weak
 * algorithms), all of which the low-level classes do by hand or not at all.
 */
public class OpenPGPApiCrypto {

    private final OpenPGPApi api;
    private final OpenPGPPolicy policy;

    /** Uses Bouncy Castle's default policy. */
    public OpenPGPApiCrypto() {
        this(new OpenPGPDefaultPolicy());
    }

    /**
     * Uses the given policy for everything: key validation, algorithm negotiation and signature
     * checks. Relax the default policy only to read old data (see the README).
     */
    public OpenPGPApiCrypto(OpenPGPPolicy policy) {
        this.api = new JcaOpenPGPApi(BCPGPUtils.PROVIDER, policy);
        this.policy = policy;
    }

    public OpenPGPApi getApi() {
        return api;
    }

    /** Reads a public key (certificate) file, binary or ASCII-armored. */
    public OpenPGPCertificate readCertificate(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return api.readKeyOrCertificate().parseCertificate(in);
        }
    }

    /** Reads a secret key file, binary or ASCII-armored. */
    public OpenPGPKey readKey(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return api.readKeyOrCertificate().parseKey(in);
        }
    }

    /**
     * Encrypts {@code input} for {@code recipient}. If {@code signingKey} is not null the message
     * is also signed with it, unlocking it with {@code signingKeyPassphrase}.
     */
    public void encryptFile(
            Path input,
            Path output,
            OpenPGPCertificate recipient,
            OpenPGPKey signingKey,
            char[] signingKeyPassphrase,
            boolean armored)
            throws IOException, PGPException {
        OpenPGPMessageGenerator generator =
                api.signAndOrEncryptMessage()
                        .setArmored(armored)
                        .setFileMetadata(input.toFile())
                        .addEncryptionCertificate(recipient);
        if (signingKey != null) {
            generator.addSigningKey(signingKey, key -> signingKeyPassphrase);
        }

        try (OutputStream fileOut = new BufferedOutputStream(Files.newOutputStream(output));
                OutputStream msgOut = generator.open(fileOut)) {
            Files.copy(input, msgOut);
        }
    }

    /**
     * Decrypts {@code input} into {@code output} with {@code decryptionKey}. If {@code signer} is
     * not null, the message must carry a valid signature from it.
     *
     * @return the processing result (signatures, encryption method, file name, ...)
     */
    public OpenPGPMessageInputStream.Result decryptFile(
            Path input,
            Path output,
            OpenPGPKey decryptionKey,
            char[] decryptionKeyPassphrase,
            OpenPGPCertificate signer)
            throws IOException, PGPException {
        OpenPGPMessageProcessor processor =
                api.decryptAndOrVerifyMessage()
                        .addDecryptionKey(decryptionKey, decryptionKeyPassphrase);
        if (signer != null) {
            processor.addVerificationCertificate(signer);
        }

        OpenPGPMessageInputStream.Result result;
        try (InputStream fileIn = Files.newInputStream(input);
                OutputStream fileOut = new BufferedOutputStream(Files.newOutputStream(output))) {
            OpenPGPMessageInputStream msgIn = processor.process(fileIn);
            try (msgIn) {
                msgIn.transferTo(fileOut);
            }
            // The result, including signature verification, is only complete once the whole
            // message has been read and the message stream closed.
            result = msgIn.getResult();
        }

        if (signer != null && !hasValidSignatureFrom(result.getSignatures(), signer)) {
            throw new PGPException("Message has no valid signature from the expected signer.");
        }
        return result;
    }

    private boolean hasValidSignatureFrom(
            List<OpenPGPDocumentSignature> signatures, OpenPGPCertificate signer)
            throws PGPException {
        for (OpenPGPDocumentSignature signature : signatures) {
            if (signature.getIssuerCertificate() != null
                    && signature
                            .getIssuerCertificate()
                            .getKeyIdentifier()
                            .equals(signer.getKeyIdentifier())
                    && signature.isValid(policy)) {
                return true;
            }
        }
        return false;
    }
}
