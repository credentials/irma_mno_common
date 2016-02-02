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

import net.sf.scuba.util.Hex;

import org.jmrtd.Util;
import org.jmrtd.lds.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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

public class EDLDataMessage extends DocumentDataMessage {

    byte[] dg1File; /* personal data */
    String documentNr; /* this is taken from the MRZ, if the BAC worked, than the MRZ was correct */
    private static final Integer aaDataGroupNumber = new Integer (13);
    private static final String rootCertFilePath = "";

    public EDLDataMessage(String sessionToken, String imsi) {
        super(sessionToken,imsi);
    }

    public EDLDataMessage(String sessionToken, String imsi, byte[] challenge) {
        super(sessionToken,imsi,challenge);
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
    protected String getRootCertFilePath() {
        return rootCertFilePath;
    }

    @Override
    protected String getPersonalDataFileAsString() {
        DriverDemographicInfo driverInfo = parseDG1();
        return "driver info: " + driverInfo.toString() + "document Number " + documentNr;
    }

    private DriverDemographicInfo parseDG1() {
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
                    in.skip(length);
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
                default:
                    in.skip(length); //we don't care about the rest of the fields for now.
            }
        }
    }

    // copied from stackoverflow
    // @url: http://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l/2197650#2197650
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
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
