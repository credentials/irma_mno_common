/*
 * Copyright (c) 2015, Wouter Lueks
 * Copyright (c) 2015, Sietse Ringers
 * Copyright (c) 2015, Fabian van den Broek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.mno.common;

import net.sf.scuba.util.Hex;

import org.jmrtd.Util;
import org.jmrtd.lds.*;

import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PassportDataMessage extends BasicClientMessage {
    private String imsi;

    SODFile sodFile;
    DG1File dg1File;
    DG14File dg14File;
    DG15File dg15File;
    byte [] challenge;
    byte [] response;


    public PassportDataMessage() {
    }

    public PassportDataMessage(String sessionToken, String imsi) {
        super(sessionToken);
        this.imsi = imsi;
    }

    public PassportDataMessage(String sessionToken, String imsi, byte[] challenge) {
        super(sessionToken);
        this.imsi = imsi;
        this.challenge = challenge;
    }

    public PassportVerificationResult verify(byte[] challenge) {
        if (!verifyHashes()) {
            return PassportVerificationResult.HASHES_INVALID;
        }

        if (!verifySignature()) {
            return PassportVerificationResult.SIGNATURE_INVALID;
        }

        if (!verifyAA(challenge)) {
            return PassportVerificationResult.AA_FAILED;
        }

        return PassportVerificationResult.SUCCESS;
    }


    /**
     * Method to verify the hashes of datagroups 1 and 15 against those present in the SOD File
     * @return
     */
    private boolean verifyHashes(){
        String digestAlg = sodFile.getDigestAlgorithm();
        Map<Integer, byte[]> hashes = sodFile.getDataGroupHashes();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(digestAlg);
        } catch (Exception e) {
            //TODO: Error!
            e.printStackTrace();
        }
        digest.update(dg1File.getEncoded());
        byte[] hash_dg1 = digest.digest();
        digest.update(dg15File.getEncoded());
        byte[] hash_dg15 = digest.digest();

        if (!Arrays.equals(hash_dg1, hashes.get(Integer.valueOf(1)))) {
            return false;
        }
        if (!Arrays.equals(hash_dg15, hashes.get(Integer.valueOf(15)))) {
            return false;
        }

        return true;
    }

    private boolean verifySignature() {
        try {
            //retrieve the Certificate used for signing the document.
            X509Certificate passportCert = sodFile.getDocSigningCertificate();

            //verify the signature over the SOD file
            if (!sodFile.checkDocSignature(passportCert)) {
                return false;
            }

            InputStream ins;
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate nlcert;
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            // Load certificates from the jar and put them in the keystore
            for (int i = 1; i <= 4; i++) {
                ins = this.getClass().getClassLoader().getResourceAsStream("nl" + i + ".cer");
                nlcert = factory.generateCertificate(ins);
                keyStore.setCertificateEntry("nl" + i, nlcert);
                ins.close();
            }

            // Found this at https://stackoverflow.com/questions/6143646/validate-x509-certificates-using-java-apis. I
            // really have _no_ clue why this works while the previous code (which was roughly along the lines of
            // http://stackoverflow.com/a/2458343) didn't...
            // The API is vastly unclear, the documentation doesn't help, and neither does the internet. We might even
            // want to consider doing the verification entirely manually. At least then we can be sure what's really
            // going on.
            // TODO revocation checking
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> mylist = new ArrayList<X509Certificate>();
            mylist.add((X509Certificate) passportCert);
            CertPath cp = cf.generateCertPath(mylist);

            PKIXParameters params = new PKIXParameters(keyStore);
            params.setRevocationEnabled(false);
            CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Verify whether the response matches the AA computation of the challenge and the private key belonging to the public key stored in DG15.
     *
     * @param challenge The challenge
     * @return true if valid, false otherwise
     */
    private boolean verifyAA(byte[] challenge) {
        PublicKey publickey = dg15File.getPublicKey();
        Signature aaSignature = null;
        MessageDigest aaDigest = null;
        Cipher aaCipher = null;
        boolean answer = false;

        try {
            if (publickey.getAlgorithm().equals("RSA")) {
                // Instantiate signature scheme, digest and cipher
                aaSignature = Signature.getInstance("SHA1WithRSA/ISO9796-2");
                aaDigest = MessageDigest.getInstance("SHA1");
                aaCipher = Cipher.getInstance("RSA/NONE/NoPadding");
                aaCipher.init(Cipher.DECRYPT_MODE, publickey);
                aaSignature.initVerify(publickey);

                int digestLength = aaDigest.getDigestLength(); /* should always be 20 */
                assert (digestLength == 20);
                byte[] plaintext = new byte[0];

                plaintext = aaCipher.doFinal(response);

                byte[] m1 = recoverMessage(digestLength, plaintext);
                aaSignature.update(m1);
                aaSignature.update(challenge);

                answer = aaSignature.verify(response);

            } else if (publickey.getAlgorithm().equals("EC")) {
                // Retrieve the signature scheme from DG14
                List<ActiveAuthenticationInfo> aaInfos = getDg14File().getActiveAuthenticationInfos();
                assert (aaInfos.size() == 1);
                ActiveAuthenticationInfo aaInfo = aaInfos.get(0);
                String oid = aaInfo.getSignatureAlgorithmOID();
                String mnenomic = ActiveAuthenticationInfo.lookupMnemonicByOID(oid);
                mnenomic = rewriteECDSAMnenomic(mnenomic);

                aaSignature = Signature.getInstance(mnenomic);
                assert (aaSignature != null);

                ECPublicKey ecPublicKey = (ECPublicKey) publickey;
                ECParameterSpec ecParams = ecPublicKey.getParams();

                aaSignature.initVerify(publickey);
                aaSignature.update(challenge);
                answer = aaSignature.verify(response);

            }
        } catch (ClassCastException         // Casting of publickey to an EC public key failed
                | NoSuchAlgorithmException  // Error initialising AA cipher suite
                | NoSuchPaddingException    // same
                | InvalidKeyException       // publickey is invalid
                | IllegalBlockSizeException // Error in aaCipher.doFinal()
                | BadPaddingException       // same
                | NumberFormatException     // Error in computing or verifying signature
                | SignatureException e) {   // same
            e.printStackTrace();
            answer = false;
        }

        return answer;
    }

    public static String rewriteECDSAMnenomic (String mnenomic) {
        if (mnenomic.equals("SHA1withECDSA")) { return "SHA1/CVC-ECDSA"; }
        if (mnenomic.equals("SHA224withECDSA")) { return "SHA224/CVC-ECDSA"; }
        if (mnenomic.equals("SHA256withECDSA")) { return "SHA256/CVC-ECDSA"; }
        if (mnenomic.equals("SHA384withECDSA")) { return "SHA348/CVC-ECDSA"; }
        if (mnenomic.equals("SHA512withECDSA")) { return "SHA512/CVC-ECDSA"; }
        if (mnenomic.equals("RIPEMD160withECDSA")) { return "RIPEMD160/CVC-ECDSA"; }

        return mnenomic;
    }

    /**
     * Recovers the M1 part of the message sent back by the AA protocol
     * (INTERNAL AUTHENTICATE command). The algorithm is described in
     * ISO 9796-2:2002 9.3.
     *
     * Based on code by Ronny (ronny@cs.ru.nl) who presumably ripped this
     * from Bouncy Castle.
     *
     * @param digestLength should be 20
     * @param plaintext response from card, already 'decrypted' (using the
     * AA public key)
     *
     * @return the m1 part of the message
     */
    public static byte[] recoverMessage(int digestLength, byte[] plaintext) {
        if (plaintext == null || plaintext.length < 1) {
            throw new IllegalArgumentException("Plaintext too short to recover message");
        }
        if (((plaintext[0] & 0xC0) ^ 0x40) != 0) {
            // 0xC0 = 1100 0000, 0x40 = 0100 0000
            throw new NumberFormatException("Could not get M1-0");
        }
        if (((plaintext[plaintext.length - 1] & 0xF) ^ 0xC) != 0) {
            // 0xF = 0000 1111, 0xC = 0000 1100
            throw new NumberFormatException("Could not get M1-1");
        }
        int delta = 0;
        if (((plaintext[plaintext.length - 1] & 0xFF) ^ 0xBC) == 0) {
            delta = 1;
        } else {
            // 0xBC = 1011 1100
            throw new NumberFormatException("Could not get M1-2");
        }

        /* find out how much padding we've got */
        int paddingLength = 0;
        for (; paddingLength < plaintext.length; paddingLength++) {
            // 0x0A = 0000 1010
            if (((plaintext[paddingLength] & 0x0F) ^ 0x0A) == 0) {
                break;
            }
        }
        int messageOffset = paddingLength + 1;

        int paddedMessageLength = plaintext.length - delta - digestLength;
        int messageLength = paddedMessageLength - messageOffset;

        /* there must be at least one byte of message string */
        if (messageLength <= 0) {
            throw new NumberFormatException("Could not get M1-3");
        }

        /* TODO: if we contain the whole message as well, check the hash of that. */
        if ((plaintext[0] & 0x20) == 0) {
            throw new NumberFormatException("Could not get M1-4");
        } else {
            byte[] recoveredMessage = new byte[messageLength];
            System.arraycopy(plaintext, messageOffset, recoveredMessage, 0, messageLength);
            return recoveredMessage;
        }
    }

    public boolean isComplete () {
        if (sodFile == null)
            return false;

        if (sodFile.getDataGroupHashes().get(14) != null && dg14File == null)
            return false;

        return imsi != null && dg1File != null && dg15File != null && response != null;
    }

    public String getImsi() {
        return imsi;
    }

    public void setImsi(String imsi) {
        this.imsi = imsi;
    }

    public SODFile getSodFile() {
        return sodFile;
    }

    public void setSodFile(SODFile sodFile) {
        this.sodFile = sodFile;
    }

    public DG1File getDg1File() {
        return dg1File;
    }

    public void setDg1File(DG1File dg1File) {
        this.dg1File = dg1File;
    }

    public DG14File getDg14File() {
        return dg14File;
    }

    public void setDg14File(DG14File dg14File) {
        this.dg14File = dg14File;
    }

    public DG15File getDg15File() {
        return dg15File;
    }

    public void setDg15File(DG15File dg15File) {
        this.dg15File = dg15File;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public void setChallenge(byte[] response) {
        this.challenge = challenge;
    }

    public byte[] getResponse() {
        return response;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public String toString() {
        return "[IMSI: " + imsi + ", Session: " + getSessionToken() + "\n"
                + "SODFile: " + sodFile.toString() +"\n"
                + "DG1:" + dg1File.toString() + "\n"
                + "DG15" + dg15File.toString() + "\n"
                + "response:" + Hex.bytesToHexString(response) + " ]";
    }
}
