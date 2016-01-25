package org.irmacard.mno.common;

/**
 * Encapsulates driver demographic info, see ISO18013-2, Section 8.1.
 * Copied from org.isodl.service.DriverDemographicInfo
 *
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */

import net.sf.scuba.util.Hex;

import java.io.IOException;
import java.io.InputStream;

public class DriverDemographicInfo {
    public String familyName = null;

    public String givenNames = null;

    public String placeOfBirth = null;

    public String dob = null;

    public String doi = null;

    public String doe = null;

    public String country = null;

    public String authority = null;

   // public String number = null; TODO this would be BSN...

    /**
     * Constructs a new object.
     *
     * @param familyName
     *            family name
     * @param givenNames
     *            given names
     * @param dob
     *            date of birth
     * @param doi
     *            date of issue
     * @param doe
     *            date of expiry
     * @param country
     *            country code (3 letters)
     * @param authority
     *            issuing authority
     * //@param number
     *            sic id number
     */
    public DriverDemographicInfo(String familyName, String givenNames,
                                 String dob, String doi, String doe, String country,
                                 String authority) {
        this.familyName = familyName;
        this.givenNames = givenNames;
        this.dob = dob;
        this.doi = doi;
        this.doe = doe;
        this.country = country;
        this.authority = authority;
       // this.number = number;
    }

    /**
     * Constructs a new file based on data in <code>in</code>.
     *
     * @param in
     *            the input stream to be decoded
     *
     * @throws IOException
     *             if decoding fails
     */
    public DriverDemographicInfo(InputStream in) throws IOException {
        int len = 0;
        byte[] t = null;
        len = in.read();
        t = new byte[len];
        in.read(t);
        familyName = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        givenNames = new String(t);
        t = new byte[4];
        in.read(t);
        dob = Hex.bytesToHexString(t);
        t = new byte[4];
        in.read(t);
        doi = Hex.bytesToHexString(t);
        t = new byte[4];
        in.read(t);
        doe = Hex.bytesToHexString(t);
        t = new byte[3];
        in.read(t);
        country = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        authority = new String(t);
        len = in.read();
        t = new byte[len];
        in.read(t);
        //number = new String(t);

    }

    public String toString() {
        return familyName + "<" + givenNames + "<" + dob + "<" + doi + "<"
                + doe + "<" + country + "<" + authority;// + "<" + number;
    }

    /**
     * Gets the encoded version of this file.
     */
    public byte[] getEncoded() {
        String[] data = { familyName, givenNames, dob, doi, doe, country,
                authority};//, number };
        int total = 0;
        for (String s : data) {
            total += s.length() + 1;
        }
        total -= 16;
        byte[] result = new byte[total];
        int offset = 0;
        for (String s : data) {
            if (s != dob && s != doi && s != doe && s != country) {
                result[offset++] = (byte) s.length();
                System.arraycopy(s.getBytes(), 0, result, offset, s.length());
                offset += s.length();
            } else {
                if (s == country) {
                    System.arraycopy(s.getBytes(), 0, result, offset, 3);
                    offset += 3;
                } else {
                    System.arraycopy(Hex.hexStringToBytes(s), 0, result,
                            offset, 4);
                    offset += 4;
                }
            }
        }
        return result;
    }



}


