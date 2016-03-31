/*
 * eDLDataMessage.java
 *
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

import org.jmrtd.lds.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.interfaces.RSAPublicKey;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.ISO9796d2Signer;
import org.spongycastle.crypto.SignerWithRecovery;

public class EDLDataMessage extends DocumentDataMessage {

    byte[] dg1File; /* personal data */
    String documentNr; /* this is taken from the MRZ, if the BAC worked, than the MRZ was correct */
    private static final Integer aaDataGroupNumber = new Integer (13);
    private static final String pathToCertificates = "_eDL_path";
    private static final String certificateFiles = "_eDL_certs";

    public EDLDataMessage(String sessionToken) {
        super(sessionToken);
    }

    public EDLDataMessage(String sessionToken, byte[] challenge) {
        super(sessionToken,challenge);
    }

    @Override
    protected byte[] getPersonalDataFileAsBytes() {
        return dg1File;
    }

    @Override
    protected Integer getAADataGroupNumber() {
        return aaDataGroupNumber;
    }

    @Override
    protected String getIssuingState() {
        return getDriverDemographicInfo().country;
    }

    @Override
    protected String getPersonalDataFileAsString() {
        DriverDemographicInfo driverInfo = getDriverDemographicInfo();
        return "driver info: " + driverInfo.toString() + "document Number " + documentNr;
    }

    @Override
    protected SignerWithRecovery getRSASigner(){
        SignerWithRecovery signer = null;
        try {
            RSAEngine rsa = new RSAEngine();
            RSAPublicKey pub = (RSAPublicKey) aaFile.getPublicKey();
            RSAKeyParameters pubParameters = new RSAKeyParameters(false,pub.getModulus(), pub.getPublicExponent());
            signer =  new ISO9796d2Signer( rsa, new SHA256Digest(), false);
            signer.init(false, pubParameters);
        } catch (Exception e){
            e.printStackTrace();
        }
        return signer;
    }

    @Override
    protected String getCertificateFilePath() {
        return pathToCertificates;
    }

    @Override
    protected String getCertificateFileList() {
        return certificateFiles;
    }


    public DriverDemographicInfo getDriverDemographicInfo() {
        DriverDemographicInfo driverInfo = new DriverDemographicInfo();
        if (dg1File == null){
            return null;
        } else {
            ByteArrayInputStream in = new ByteArrayInputStream(dg1File);
            try {
            int t = in.read();
            while ( t !=-1){
                if (t == 95 /*0x5F start of tag*/){
                    readObject(driverInfo,in);
                }
                t = in.read();
            }
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }
        return driverInfo;
    }

    private void readObject(DriverDemographicInfo driverInfo,InputStream in) throws IOException {
        int t2 = in.read();
        int length = in.read();
        byte[] contents = new byte[length];
        if (t2 != -1 || length !=-1){
            switch (t2) {
                case 01:
                    in.skip(length);/*unsure what this field represents*/
                    break;
                case 02://unclear why, but this field contains no length...
                    break;
                case 03: //country of issuance
                    in.read(contents,0,length);
                    driverInfo.setCountry(new String(contents));
                    break;
                case 04://last name
                    in.read(contents,0,length);
                    driverInfo.setFamilyName(new String(contents));
                    break;
                case 05: //first name
                    in.read(contents,0,length);
                    driverInfo.setGivenNames(new String(contents));
                    break;
                case 06: //birth date
                    in.read(contents, 0, length);
                    driverInfo.setDob(bytesToHex(contents));
                    break;
                case 07: // birth place
                    in.read(contents,0,length);
                    driverInfo.setPlaceOfBirth(new String(contents));
                    break;
                case 10: // doi
                    in.read(contents,0,length);
                    driverInfo.setDoi(bytesToHex(contents));
                    break;
                case 11: // doe
                    in.read(contents,0,length);
                    driverInfo.setDoe(bytesToHex(contents));
                    break;
                default:
                    in.skip(length); //we don't care about the rest of the fields for now.
            }
        }
    }


    public byte[] getDg1File() {
        return dg1File;
    }

    public void setDg1File(byte[] dg1File) {
        this.dg1File = dg1File;
    }

    public DG15File getDg13File() {
        return getAaFile();
    }

    public void setDg13File(DG15File dg13File) {
        setAaFile(dg13File);
    }

    public DG14File getDg14File(){
        return getEaFile();
    }

    public void setDg14File(DG14File dg14File) {
        setEaFile(dg14File);
    }

    public String getDocumentNr() {
        return documentNr;
    }

    public void setDocumentNr(String documentNr) {
        this.documentNr = documentNr;
    }

}
