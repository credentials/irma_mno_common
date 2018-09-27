package org.irmacard.mno.common;

import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.jmrtd.lds.icao.*;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;

public class PassportData extends AbstractEIdData{
    DG1File dg1File;    /* MRZ */
    private static final Integer aaDataGroupNumber = new Integer(15);
    private static final String pathToCertificates = "_passport_path";
    private static final String certificateFiles = "_passport_certs";

    public PassportData() {
        this.scheme_manager = "desk-demo";
        this.issuer = "RU";
        this.credential = "passport";
    }

    public PassportData(byte[] challenge) {
        this.challenge= challenge;
        this.scheme_manager = "desk-demo";
        this.issuer = "RU";
        this.credential = "passport";
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
    public HashMap<String, String> getIssuingJWT(){
        HashMap<String, String> attrs = new HashMap<>();
        SimpleDateFormat bacDateFormat = new SimpleDateFormat("yyMMdd");
        SimpleDateFormat hrDateFormat = new SimpleDateFormat("MMM d, y"); // Matches Android's default date format
        Date dob = null;
        Date expiry = null;
        MRZInfo mrz = dg1File.getMRZInfo();
        try {
            dob = bacDateFormat.parse(mrz.getDateOfBirth());
            expiry = bacDateFormat.parse(mrz.getDateOfExpiry());
        }  catch (ParseException e) {
            e.printStackTrace();
        }

        attrs.put("firstnames", toTitleCase(joinStrings(mrz.getSecondaryIdentifierComponents())));
        attrs.put("familyname", mrz.getPrimaryIdentifier());
        attrs.put("dateofbirth",hrDateFormat.format(dob));
        attrs.put("gender",mrz.getGender().name());
        attrs.put("nationality",mrz.getNationality());
        attrs.put("number", mrz.getDocumentNumber());
        attrs.put("expires", hrDateFormat.format(expiry));

        return attrs;
    }

    @Override
    public String getDataToReview() {
        StringBuilder sb = new StringBuilder();
        MRZInfo mrz = dg1File.getMRZInfo();

        SimpleDateFormat bacDateFormat = new SimpleDateFormat("yyMMdd");
        SimpleDateFormat hrDateFormat = new SimpleDateFormat("MMM d, y");
        Date dob;
        Date expiry;

        sb.append("Family name: ").append(mrz.getPrimaryIdentifier()).append("<br/>");
        sb.append("First names: ").append(mrz.getSecondaryIdentifier()).append("<br/>");
        try {
            dob = bacDateFormat.parse(mrz.getDateOfBirth());
            sb.append("Birth date: ").append(hrDateFormat.format(dob)).append("<br/>");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        sb.append("<br/>");
        try {
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
    protected SignerWithRecovery getRSASigner() {
        SignerWithRecovery signer = null;
        try {
            RSAEngine rsa = new RSAEngine();
            RSAPublicKey pub = (RSAPublicKey) getPublicKey(aaFile);
            RSAKeyParameters pubParameters = new RSAKeyParameters(false, pub.getModulus(), pub.getPublicExponent());
            signer = new ISO9796d2Signer(rsa, new SHA1Digest(), true);
            signer.init(false, pubParameters);
        } catch (Exception e /* response value is not correct*/) {
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

        for (int i = 1; i < parts.length; i++) {
            s += glue + parts[i];
        }

        return s;
    }

}


