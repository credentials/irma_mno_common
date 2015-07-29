/*
 * PassportDataMessage.java
 *
 * Copyright (c) 2015, Wouter Lueks, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.mno.common;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.DG15File;
import org.jmrtd.lds.DG1File;
import org.jmrtd.lds.SODFile;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class PassportDataMessage extends BasicClientMessage {
    private String imsi;

    SODFile sodFile;
    DG1File dg1File;
    DG15File dg15File;
    byte [] response;

    PassportService passportService;


    public PassportDataMessage() {
    }

    public PassportDataMessage(String sessionToken, String imsi, PassportService ps) {
        super(sessionToken);
        this.imsi = imsi;
        passportService = ps;
    }


    public boolean readPassport(byte[] challenge) throws CardServiceException, IOException {
        if (passportService != null) {
            if (dg1File == null)
                dg1File = new DG1File(passportService.getInputStream(PassportService.EF_DG1));
            if (dg15File == null)
                dg15File =  new DG15File(passportService.getInputStream(PassportService.EF_DG15));
            if (sodFile == null)
                sodFile = new SODFile(passportService.getInputStream(PassportService.EF_SOD));
        }

        if (dg1File == null || dg15File == null || sodFile == null) {
            return false;
        }

        //Active Authentication
        //The following 5 rules do the same as the following commented out command, but set the expected length field to 0 instead of 256.
        //This can be replaced by the following rule once JMRTD is fixed.
       //response = passportService.sendInternalAuthenticate(passportService.getWrapper(), challenge);
        CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, challenge,256);
       // System.out.println("CAPDU: " + Hex.bytesToSpacedHexString(capdu.getBytes()));
        APDUWrapper wrapper = passportService.getWrapper();
        CommandAPDU wrappedCApdu = wrapper.wrap(capdu);

      //  System.out.println("CAPDU: " + Hex.bytesToSpacedHexString(wrappedCApdu.getBytes()));
        ResponseAPDU rapdu = passportService.transmit(wrappedCApdu);
       // int sw = rapdu.getSW();
       // System.out.println("STATUS WORDS: "+ sw);
        rapdu = wrapper.unwrap(rapdu, rapdu.getBytes().length);
        response = rapdu.getData();

        return response != null;
    }

    public PassportVerificationResult verify(byte[] challenge) {
        System.out.println("challenge:" + Hex.bytesToHexString(challenge));
        System.out.println(this.toString());
        if (!verifyHashes()) {
            return PassportVerificationResult.HASHES_INVALID;
        }

        if (!verifySignature()) {
            return PassportVerificationResult.SIGNATURE_INVALID;
        }

        if (!verifyAA(challenge)) {
            // TODO Give apropriate error
            return PassportVerificationResult.SUCCESS;
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

    private boolean verifyAA(byte[] challenge){
        //verify whether the response matches the AA computation of the challenge and the private key belonging to the public key stored in DG15
        //initialise ciphersuite
        Signature aaSignature = null;
        MessageDigest aaDigest = null;
        Cipher aaCipher = null;
        try{
            aaSignature = Signature.getInstance("SHA1WithRSA/ISO9796-2");
            aaDigest = MessageDigest.getInstance("SHA1");
            aaCipher = Cipher.getInstance("RSA/NONE/NoPadding");
        } catch (Exception e){
            e.printStackTrace();
            //TODO: Error initialising AA cipher suite
        }

        PublicKey publickey = dg15File.getPublicKey();
        try {
            aaCipher.init(Cipher.DECRYPT_MODE, publickey);
            aaSignature.initVerify(dg15File.getPublicKey());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        int digestLength = aaDigest.getDigestLength(); /* should always be 20 */
        assert(digestLength == 20);
        byte[] plaintext = new byte[0];
        try {
            plaintext = aaCipher.doFinal(response);
            System.out.println("plaintext:" + Hex.bytesToPrettyString(plaintext));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        //Util is now deprecated in JMRTD
        try {
            byte[] m1 = recoverMessage(digestLength, plaintext);
            aaSignature.update(m1);
            aaSignature.update(challenge);
        } catch (NumberFormatException|SignatureException e) {
            e.printStackTrace();
        }

        boolean success = false;
        try {
            success = aaSignature.verify(response);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return success;
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
        return imsi != null && sodFile != null && dg1File != null && dg15File != null && response != null;
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

    public DG15File getDg15File() {
        return dg15File;
    }

    public void setDg15File(DG15File dg15File) {
        this.dg15File = dg15File;
    }

    public byte[] getResponse() {
        return response;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public PassportService getPassportService() {
        return passportService;
    }

    public void setPassportService(PassportService passportService) {
        this.passportService = passportService;
    }

    public String toString() {
        return "[IMSI: " + imsi + ", Session: " + getSessionToken() + "\n"
                + "SODFile: " + sodFile.toString() +"\n"
                + "DG1:" + dg1File.toString() + "\n"
                + "DG15" + dg15File.toString() + "\n"
                + "response:" + Hex.bytesToHexString(response) + " ]";
    }
}
