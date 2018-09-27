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

import org.jmrtd.lds.icao.*;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;

public class PassportDataMessage extends DocumentDataMessage  {

    DG1File dg1File;    /* MRZ */
    DG5File dg5File;   /* passphoto */
    private static final Integer aaDataGroupNumber = new Integer (15);
    private static final String pathToCertificates = "_passport_path";
    private static final String certificateFiles = "_passport_certs";

    public PassportDataMessage(String sessionToken) {
        super(sessionToken);
    }

    public PassportDataMessage(String sessionToken, byte[] challenge) {
        super(sessionToken,challenge);
    }

    @Override
    protected byte[] getPersonalDataFileAsBytes() {
        return dg1File.getEncoded();
    }

    @Override
    protected Integer getAADataGroupNumber() {
        return aaDataGroupNumber;
    }

    @Override
    public String getIssuingState() {
        return getDg1File().getMRZInfo().getIssuingState();
    }

    @Override
    protected String getPersonalDataFileAsString() {
        return dg1File.getMRZInfo().toString();
    }

    @Override
    public String getDataToReview(){
        StringBuilder sb = new StringBuilder();
        MRZInfo mrz = dg1File.getMRZInfo();
        String[] nameParts = splitFamilyName(mrz.getPrimaryIdentifier());
        // The first of the first names is not always the person's usual name ("roepnaam"). In fact, the person's
        // usual name need not even be in his list of first names at all. But given only the MRZ, there is no way of
        // knowing what is his/her usual name... So we can only guess.
        String firstname = toTitleCase(mrz.getSecondaryIdentifierComponents()[0]);

        SimpleDateFormat bacDateFormat = new SimpleDateFormat("yyMMdd");
        SimpleDateFormat hrDateFormat = new SimpleDateFormat("MMM d, y");
        Date dob;
        Date expiry;

        sb.append("Family name: ").append(nameParts[0]).append(" ").append(toTitleCase(nameParts[1])).append("<br/>");
        sb.append("Given name: ").append(firstname).append("<br/>");
        try {
            dob = bacDateFormat.parse(mrz.getDateOfBirth());
            sb.append("Birth date: ").append(hrDateFormat.format(dob)).append("<br/>");
        }  catch (ParseException e) {
            e.printStackTrace();
        }
        sb.append("<br/>");
        try{
            expiry = bacDateFormat.parse(mrz.getDateOfExpiry());
            sb.append("Expiry date ").append(hrDateFormat.format(expiry)).append("<br/>");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        sb.append("Document type: ").append(mrz.getDocumentType()).append("<br/>");
        sb.append("Document number: ").append(mrz.getDocumentNumber()).append("<br/>");

        return sb.toString();
    }

    @Override
    protected SignerWithRecovery getRSASigner(){
        SignerWithRecovery signer = null;
        try {
            RSAEngine rsa = new RSAEngine();
            RSAPublicKey pub = (RSAPublicKey) getPublicKey(aaFile);
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, pub.getModulus(), pub.getPublicExponent());
            signer = new ISO9796d2Signer(rsa, new SHA1Digest(), true);
            signer.init(false, pubParameters);
        } catch (Exception e /* response value is not correct*/){
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

    public DG14File getDg14File() {
        return getEaFile();
    }

    public void setDg14File(DG14File dg14File) {
        setEaFile(dg14File);
    }

    public DG15File getDg15File() {
        return getAaFile();
    }

    public void setDg15File(DG15File dg15File) {
        setAaFile(dg15File);
    }

    public DG1File getDg1File() {
        return dg1File;
    }

    public void setDg1File(DG1File dg1File) {
        this.dg1File = dg1File;
    }

    public DG5File getDg5File() {
        return dg5File;
    }

    public void setDg5File(DG5File dg5File) {
        this.dg5File = dg5File;
    }

    /**
     * Try to split the family name in into a prefix and a proper part, using a list of commonly occuring (Dutch)
     * prefixes.
     * @param name The name to split
     * @return An array in which the first element is the prefix, or " " if none found, and the second is the
     * remainder of the name.
     */
    public String[] splitFamilyName(String name) {
        name = name.toLowerCase();
        String[] parts = {" ", name};

        // Taken from https://nl.wikipedia.org/wiki/Tussenvoegsel
        String[] prefixes = {"af", "aan", "bij", "de", "den", "der", "d'", "het", "'t", "in", "onder", "op", "over", "'s", "'t", "te", "ten", "ter", "tot", "uit", "uijt", "van", "vanden", "ver", "voor", "aan de", "aan den", "aan der", "aan het", "aan 't", "bij de", "bij den", "bij het", "bij 't", "boven d'", "de die", "de die le", "de l'", "de la", "de las", "de le", "de van der,", "in de", "in den", "in der", "in het", "in 't", "onder de", "onder den", "onder het", "onder 't", "over de", "over den", "over het", "over 't", "op de", "op den", "op der", "op gen", "op het", "op 't", "op ten", "van de", "van de l'", "van den", "van der", "van gen", "van het", "van la", "van 't", "van ter", "van van de", "uit de", "uit den", "uit het", "uit 't", "uit te de", "uit ten", "uijt de", "uijt den", "uijt het", "uijt 't", "uijt te de", "uijt ten", "voor de", "voor den", "voor in 't"};

        // I'm too lazy to manually sort the list above on string size.
        Arrays.sort(prefixes, new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                if (o1.length() < o2.length()) return 1;
                if (o1.length() > o2.length()) return -1;
                return o1.compareTo(o2);
            }
        });

        for (String prefix : prefixes) {
            if (name.startsWith(prefix + " ")) {
                parts[0] = prefix;
                parts[1] = name.substring(prefix.length() + 1); // + 1 to skip the space between the prefix and the name
                return parts;
            }
        }

        return parts;
    }

    public static String toTitleCase(String s) {
        String ACTIONABLE_DELIMITERS = " '-/"; // these cause the character following to be capitalized

        StringBuilder sb = new StringBuilder();
        boolean capitalizeNext = true;

        for (char c : s.toCharArray()) {
            c = capitalizeNext ? Character.toUpperCase(c) : Character.toLowerCase(c);
            sb.append(c);
            capitalizeNext = (ACTIONABLE_DELIMITERS.indexOf(c) >= 0);
        }

        return sb.toString();
    }

    public static String joinStrings(String[] parts) {
        if (parts.length == 0)
            return "";

        String glue = " ";

        String s = parts[0];

        for (int i=1; i<parts.length; i++) {
            s += glue + parts[i];
        }

        return s;
    }

}
