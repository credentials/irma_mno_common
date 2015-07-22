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

import org.jmrtd.PassportService;
import org.jmrtd.Util;
import org.jmrtd.lds.DG15File;
import org.jmrtd.lds.DG1File;
import org.jmrtd.lds.SODFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
        //resp = passportService.sendInternalAuthenticate(passportService.getWrapper(), challenge);
        CommandAPDU capdu = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, challenge, 0);
        APDUWrapper wrapper = passportService.getWrapper();
        CommandAPDU wrappedCApdu = wrapper.wrap(capdu);
        ResponseAPDU rapdu = passportService.transmit(wrappedCApdu);
        response = rapdu.getBytes();

        return response != null;
    }

    public boolean verify(byte[] challenge){
        if (!verifyHashes()){
            //Give apropriate error
        }
        if (!verifySignature()){
            //Give apropriate error
        }
        if (!verifyAA(challenge)){
            //Give apropriate error
        }
        return true;
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

            // Read the Dutch root certificates
            InputStream ins = this.getClass().getClassLoader().getResourceAsStream("nl1.cer");
            Certificate NLCert1 = CertificateFactory.getInstance("X.509").generateCertificate(ins);
            ins.close();

            ins = this.getClass().getClassLoader().getResourceAsStream("nl2.cer");
            Certificate NLCert2 = CertificateFactory.getInstance("X.509").generateCertificate(ins);
            ins.close();

            ins = this.getClass().getClassLoader().getResourceAsStream("nl3.cer");
            Certificate NLCert3 = CertificateFactory.getInstance("X.509").generateCertificate(ins);
            ins.close();

            ins = this.getClass().getClassLoader().getResourceAsStream("nl4.cer");
            Certificate NLCert4 = CertificateFactory.getInstance("X.509").generateCertificate(ins);
            ins.close();

            //and put them in a set of trustAnchors.
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.add(new TrustAnchor((X509Certificate) NLCert1, null));
            trustAnchors.add(new TrustAnchor((X509Certificate) NLCert2, null));
            trustAnchors.add(new TrustAnchor((X509Certificate) NLCert3, null));
            trustAnchors.add(new TrustAnchor((X509Certificate) NLCert4, null));

            //the starting certificate
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(passportCert);

            PKIXBuilderParameters params =
                    new PKIXBuilderParameters(trustAnchors, selector);
            params.setRevocationEnabled(false);
            //TODO at some point we will need to do revocation checks

            // Build and verify the certification chain
            // An exception will be thrown if the certificate check fails
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result =
                    (PKIXCertPathBuilderResult) builder.build(params);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
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
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        //Util is now deprecated in JMRTD
        byte[] m1 = Util.recoverMessage(digestLength, plaintext);
        try {
            aaSignature.update(m1);
            aaSignature.update(challenge);
        } catch (SignatureException e) {
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
        return "[IMSI: " + imsi + ", Session: " + getSessionToken() + "]";
    }
}
