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

import net.sf.scuba.tlv.TLVInputStream;

import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG15File;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;

public class EDLDataMessage extends DocumentDataMessage {

    private static final Integer aaDataGroupNumber = new Integer (13);
    private static final String pathToCertificates = "_eDL_path";
    private static final String certificateFiles = "_eDL_certs";

    public static final short dg1FileId = 0x0001;
    public static final int dg1Tag = 0x61;
    public static final short sodFileId = 0x001d;
    public static final short eaFileId = 0x000e;
    public static final short aaFileId = 0x000d;
    public static final short portraitFileID = 0x0005;
    public static final int portraitTag = 0x67;


    byte[] dg1File; /* personal data */
    String documentNr; /* this is taken from the MRZ, if the BAC worked, than the MRZ was correct */

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
    public String getDataToReview(){
        StringBuilder sb = new StringBuilder();
        DriverDemographicInfo driverInfo = getDriverDemographicInfo();
        sb.append("Given name: ").append(driverInfo.getGivenNames()).append("<br/>" );
        sb.append("Family name: ").append(driverInfo.getFamilyName()).append("<br/>");
        sb.append("Birth date: ").append(driverInfo.getDob()).append("<br/><br/>");
        sb.append("Document type: Driving license<br/>");
        sb.append("Licensed for: ").append(getCategories()).append("<br/>");
        sb.append("Document number: ").append(documentNr).append("<br/>");
        sb.append("Authority: ").append(driverInfo.getAuthority()).append("<br/>");
        sb.append("Country: ").append(driverInfo.getCountry()).append("<br/>");
        sb.append("Date of issuance: ").append(driverInfo.getDoi()).append("<br/>");
        sb.append("Date of expiry:").append(driverInfo.getDoe());
        return sb.toString();
    }

    @Override
    protected SignerWithRecovery getRSASigner(){
        SignerWithRecovery signer = null;
        try {
            RSAEngine rsa = new RSAEngine();
            RSAPublicKey pub = (RSAPublicKey) getPublicKey(aaFile);
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

    /*
     *@returns a String representing a summary of allowed driving categories
     */
    public String getCategories(){
        String categories = "-";
        boolean outerTag = false;
        for (int i=0; i< dg1File.length;i++){
            if (!outerTag) {
                // skip to the occurence of 7F63
                if (dg1File[i] == (byte) 0x7F) {
                    if (dg1File[i + 1] == 0x63) {
                        i++;
                        outerTag = true;
                        continue;
                    } else {
                        continue;
                    }
                }
            } else {
                //inside categories tag, find tag 0x87 for new category
                byte b = dg1File[i];
                if (b == (byte) 0x87){
                    String category = "";
                    for (i+=2/*skip length*/; i< dg1File.length; i++){
                        byte cat = dg1File[i];
                        if (cat == (byte) 0x3B){
                            category+="-";
                            categories += category;
                            break;
                        } else {
                            category += (char) cat;
                        }

                    }
                }
            }
        }
        //categories now might contain to much, e.g. BE supersedes B and categories can be mentioned double
        StringBuilder summary = new StringBuilder();
        if (categories.contains("-AM-")){
            summary.append("AM-");
        }
        if (categories.contains("-A1-")){
            if (categories.contains("-A2-")){
                if (categories.contains("-A-")){
                    summary.append("A-");
                } else {
                    summary.append("A2-");
                }
            } else {
                summary.append("A1-");
            }
        }
        if (categories.contains("-B1-") && !categories.contains("-B-")){
            summary.append("B1-");
        }
        if (categories.contains("-B-")){
            if (categories.contains("-BE-")){
                summary.append("BE-");
            } else {
                summary.append("B-");
            }
        }
        if (categories.contains("-C1-")) {
            if (categories.contains("-C-")) {
                if (categories.contains("-CE-")) {
                    summary.append("CE-");
                } else {
                    summary.append("C-");
                }
            } else {
                if (categories.contains("-C1E-")) {
                    summary.append("C1E-");
                } else {
                    summary.append("C1-");
                }
            }
        } else {
            if (categories.contains("-C-")) {
                if (categories.contains("-CE-")) {
                    summary.append("CE-");
                } else {
                    summary.append("C-");
                }
            }
        }
        if (categories.contains("-D1-")) {
            if (categories.contains("-D-")) {
                if (categories.contains("-DE-")) {
                    summary.append("DE-");
                } else {
                    summary.append("D-");
                }
            } else {
                if (categories.contains("-D1E-")) {
                    summary.append("D1E-");
                } else {
                    summary.append("D1-");
                }
            }
        } else {
            if (categories.contains("-D-")) {
                if (categories.contains("-DE-")) {
                    summary.append("DE-");
                } else {
                    summary.append("D-");
                }
            }
        }
        if (categories.contains("-T-")){
            summary.append("T-");
        }
        return summary.substring(0,summary.length()-1);
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
