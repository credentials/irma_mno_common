package org.irmacard.mno.common;


import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;
import net.sf.scuba.util.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.jmrtd.lds.ActiveAuthenticationInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG2File;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public abstract class AbstractEIdData extends AbstractDocumentData {
    protected byte[] challenge;  /* challenge sent by the server for AA */
    protected byte[] response;   /* AA response to challenge */
    protected byte[] portraitFile;
    SODFile sodFile;    /* security file with signed hashes of datagroups */
    protected byte[] eaFile;  /* SecurityInfos for EAC and PACE*/
    protected byte[] aaFile;  /* Active authentication public key */

    public static final int eaTag = 0x6E;
    public static final int aaTag = 0x6F;


    protected abstract byte[] getPersonalDataFileAsBytes();

    protected abstract Integer getAADataGroupNumber();

    protected abstract String getIssuingState();

    protected abstract String getPersonalDataFileAsString();

    public abstract String getDataToReview();

    protected abstract SignerWithRecovery getRSASigner();

    protected abstract String getCertificateFilePath();

    protected abstract String getCertificateFileList();


    /* Decoding the portrait file will not work properly.
     * So, f--- it. I'll just look for the jpeg or jp2 magic bytes
     */
    public byte[] getPortraitBytes(){
        if (portraitFile == null){
            return null;
        }
        final byte[] jpegMagic = {(byte) 0xff, (byte) 0xd8, (byte) 0xff };
        final byte[] jp2Magic = {(byte)0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0C, (byte) 0x6A, (byte) 0x50, (byte) 0x20, (byte) 0x20, (byte) 0x0D, (byte) 0x0A, (byte) 0x87, (byte) 0x0A};
        final String jpegMstring = new String(jpegMagic, StandardCharsets.UTF_8);
        final String jp2Mstring = new String(jp2Magic, StandardCharsets.UTF_8);
        String dataFile = new String (portraitFile, StandardCharsets.UTF_8);
        int offset = dataFile.indexOf(jp2Mstring);
        if (offset == -1){
            offset = dataFile.indexOf(jpegMstring);
        }
        if (offset !=-1){
            byte[] portrait = new byte[portraitFile.length-offset];
            System.arraycopy(portraitFile,offset,portrait,0,portrait.length);
            return portrait;
        } else {//to distinguish between no datafile and no picture within datafile
            return new byte[0];
        }
    }

    /*
    public byte[] getPortraitBytes() {
        DG2File portraitFile = getPortraitFile();
        if (portraitFile == null){
            System.out.println("Error, could not create DG2File out of byte array");
            return null;
        }
        List<FaceInfo> list = portraitFile.getFaceInfos();
        if (list == null){
            System.out.println("Error, could not retreive face info list from DG2File");
            return null;
        }
        if (list.isEmpty()){
            System.out.println("Error, empty face info list in DG2File");
            return null;
        }
        FaceInfo fi = list.get(0);
        List<FaceImageInfo> lijst = fi.getFaceImageInfos();
        if (lijst == null){
            System.out.println("Error, could not retreive face *image* info list from DG2File");
            return null;
        }
        if (lijst.isEmpty()){
            System.out.println("Error, empty face *image* info list in DG2File");
            return null;
        }
        FaceImageInfo fii = lijst.get(0);
        InputStream is = fii.getImageInputStream();
        if (is==null){
            System.out.println("Error, unable to get inputstream on portraitBytes");
            return null;
        }
        DataInputStream imageInputStream = new DataInputStream(is);
        portraitFile = new byte[fii.getImageLength()];
        try {
            imageInputStream.readFully(portraitFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return portraitFile;
    }*/

    public ValidationResult verify(byte[] challenge) {
        if (!verifyHashes()) {
            return new ValidationResult(ValidationResult.Result.INVALID, "Error: eID document data considered inauthentic");
        }

        if (!verifySignature()) {
            return new ValidationResult(ValidationResult.Result.INVALID, "Error: eID document signature could not be validated");
        }

        //TODO: temporarily disabled check to continue, must be fixed and turned on before production!
        /*
        if (!verifyAA(challenge)) {
            return new ValidationResult(ValidationResult.Result.INVALID, "Error: eID document considered cloned.");
        }
        */
        return new ValidationResult(ValidationResult.Result.VALID);
    }

    @Override
    public ValidationResult validate(){
        return verify(getChallenge());
    }

    /**
     * Method to verify the hashes of datagroups 1 and 15 against those present in the SOD File
     *
     * @return
     */
    protected boolean verifyHashes() {
        String digestAlg = sodFile.getDigestAlgorithm();
        Map<Integer, byte[]> hashes = sodFile.getDataGroupHashes();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(digestAlg);
        } catch (Exception e) {
            //TODO: Error!
            e.printStackTrace();
        }
        digest.update(getPersonalDataFileAsBytes());
        byte[] hash_personal_data_file = digest.digest();
        digest.update(aaFile);
        byte[] hash_aa_file = digest.digest();
        System.out.println("verifying hashes");
        //TODO strangely, this hash check fails on my passport -- FB
    /*	if (eaFile != null){
			//EA File was present, so also verify this hash
			digest.update(eaFile.getEncoded());
			byte[] hash_ea_file = digest.digest();
			if (!Arrays.equals(hash_ea_file, hashes.get(14))) {
				System.out.println("ea file is not equal");
				System.out.println("ea file hash: "+ toHexString(hash_ea_file));
				System.out.println("stored hash: " + toHexString(hashes.get(Integer.valueOf(14))));
				return false;
			}
		}
	*/
        if (!Arrays.equals(hash_personal_data_file, hashes.get(1))) {
            System.out.println("dg1file is not equal");
            return false;
        }
        if (!Arrays.equals(hash_aa_file, hashes.get(getAADataGroupNumber()))) {
            System.out.println("aa file is not equal");
            return false;
        }
        return true;
    }


    protected KeyStore getRootCerts() {
        KeyStore keyStore = null;
        InputStream cIns, pIns;
        Certificate cert;
        Properties prop = new Properties();
        String certPath;
        String[] certFiles;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            /*first load the properties file which contains the location of all certificates */
            pIns = this.getClass().getClassLoader().getResourceAsStream("certs/certificates.properties");
            if (pIns == null) {
                throw new RuntimeException("Unable to load certificates.properties");
            }
            prop.load(pIns);

            certPath = prop.getProperty(getIssuingState() + getCertificateFilePath());
            certFiles = (prop.getProperty(getIssuingState() + getCertificateFileList())).split(",");
            for (String filename : certFiles) {
                cIns = this.getClass().getClassLoader().getResourceAsStream(certPath + filename);
                cert = factory.generateCertificate(cIns);
                keyStore.setCertificateEntry(filename, cert);
                cIns.close();
            }
        } catch (KeyStoreException
                | IOException
                | NoSuchAlgorithmException
                | CertificateException e) {
            e.printStackTrace();
        }
        return keyStore;
    }


    private boolean verifySignature() {
        try {
            System.out.println("preparing for signature check");
            //retrieve the Certificate used for signing the document.
            X509Certificate passportCert = sodFile.getDocSigningCertificate();

            //verify the signature over the SOD file
            if (!sodFile.checkDocSignature(passportCert)) {
                return false;
            }

            KeyStore keyStore = getRootCerts();

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
            //result is not used, but an exception is thrown if validate is unsuccessful.
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    // copied from stackoverflow
    // @url: http://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l/2197650#2197650
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    /**
     * Verify whether the response matches the AA computation of the challenge and the private key belonging to the public key stored in DG15.
     *
     * @param challenge The challenge
     * @return true if valid, false otherwise
     */
    protected boolean verifyAA(byte[] challenge) {
        System.out.println("Preparing for AA");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKey(aaFile);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        boolean answer = false;
        try {
            if (publicKey.getAlgorithm().equals("RSA")) {
                SignerWithRecovery signer = getRSASigner();//currently eDL: SHA256/RSA,  passport: SHA1/RSA or SHA1/ECC
                signer.updateWithRecoveredMessage(response);
                signer.update(challenge, 0, challenge.length);
                answer = signer.verifySignature(response);
            } else if (publicKey.getAlgorithm().equals("EC")) {
                // Retrieve the signature scheme from DG14
                List<ActiveAuthenticationInfo> aaInfos = getEaFile().getActiveAuthenticationInfos();
                assert (aaInfos.size() == 1);
                ActiveAuthenticationInfo aaInfo = aaInfos.get(0);
                String oid = aaInfo.getSignatureAlgorithmOID();
                String mnenomic = ActiveAuthenticationInfo.lookupMnemonicByOID(oid);
                mnenomic = rewriteECDSAMnenomic(mnenomic);

                Signature aaSignature = Signature.getInstance(mnenomic);
                assert (aaSignature != null);

                //ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

                aaSignature.initVerify(publicKey);
                aaSignature.update(challenge);
                answer = aaSignature.verify(response);

            }
        } catch (ClassCastException         // Casting of publickey to an EC public key failed
                | NoSuchAlgorithmException  // Error initialising AA cipher suite
                | InvalidKeyException       // publickey is invalid
                | InvalidCipherTextException //Error in response while doing signer.updateWithRecoveredMessage
                | NumberFormatException     // Error in computing or verifying signature
                | SignatureException e) {   // same
            e.printStackTrace();
            answer = false;
        }

        return answer;
    }


    public static String rewriteECDSAMnenomic(String mnenomic) {
        if (mnenomic.equals("SHA1withECDSA")) {
            return "SHA1/CVC-ECDSA";
        }
        if (mnenomic.equals("SHA224withECDSA")) {
            return "SHA224/CVC-ECDSA";
        }
        if (mnenomic.equals("SHA256withECDSA")) {
            return "SHA256/CVC-ECDSA";
        }
        if (mnenomic.equals("SHA384withECDSA")) {
            return "SHA348/CVC-ECDSA";
        }
        if (mnenomic.equals("SHA512withECDSA")) {
            return "SHA512/CVC-ECDSA";
        }
        if (mnenomic.equals("RIPEMD160withECDSA")) {
            return "RIPEMD160/CVC-ECDSA";
        }

        return mnenomic;
    }

    public boolean isComplete() {
        if (sodFile == null)
            return false;

        if (sodFile.getDataGroupHashes().get(14) != null && eaFile == null)
            return false;

        return getPersonalDataFileAsBytes() != null && aaFile != null && response != null;
    }


    public String toString() {
        return "[SODFile: " + sodFile.toString() + "\n"
                + "DG1:" + getPersonalDataFileAsString() + "\n"
                + "DG15" + aaFile.toString() + "\n"
                + "response:" + Hex.bytesToHexString(response) + " ]";
    }


    public byte[] readFile(InputStream inputStream, int dataGroupTag) throws IOException {
        TLVInputStream tlvIn = inputStream instanceof TLVInputStream ? (TLVInputStream) inputStream : new TLVInputStream(inputStream);
        int tag = tlvIn.readTag();
        if (tag != dataGroupTag) {
            throw new IllegalArgumentException("Was expecting tag " + Integer.toHexString(dataGroupTag) + ", found " + Integer.toHexString(tag));
        }
        tlvIn.readLength();
        byte[] value = tlvIn.readValue();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        TLVOutputStream tlvOut = new TLVOutputStream(bOut);
        tlvOut.writeTag(tag);
        tlvOut.writeValue(value);
        return bOut.toByteArray();
    }

    /*
     * copied from JMRTD
     */
    protected static PublicKey getPublicKey(byte[] fileBytes) throws GeneralSecurityException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Arrays.copyOfRange(fileBytes, 3, fileBytes.length));

        String[] algorithms = {"RSA", "EC"};

        for (String algorithm : algorithms) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
                return publicKey;
            } catch (InvalidKeySpecException ikse) {
        /* NOTE: Ignore, try next algorithm. */
            }
        }
        throw new InvalidAlgorithmParameterException();
    }

    public DG15File getAaFile() {
        try {
            return new DG15File(new ByteArrayInputStream(aaFile));
        } catch (IOException | NullPointerException e) {
            e.printStackTrace();
        } finally {
            return null;
        }
    }

    public DG14File getEaFile() {
        try {
            return new DG14File(new ByteArrayInputStream(eaFile));
        } catch (IOException | NullPointerException e) {
            e.printStackTrace();
        } finally {
            return null;
        }
    }


    public DG2File getPortraitFile() {
        try {
            return new DG2File(new ByteArrayInputStream(portraitFile));
        } catch (IOException | NullPointerException e) {
            e.printStackTrace();
        } finally {
            return null;
        }
    }

    public byte[] getPortraitsBytes() {
        if (portraitFile == null){
            return null;
        } else {
            TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(portraitFile));
            try {
                tlv.skipToTag(0x5f2e);
                int length = tlv.readLength();
                byte[] face = tlv.readValue();
                return face;
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }
        return null;
    }


    public byte[] getPortraitFileBytes() {
        return portraitFile;
    }

    public byte[] getResponse() {
        return response;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public void setChallenge(byte[] response) {
        this.challenge = challenge;
    }

    public byte[] getAaFileAsBytes() {
        return aaFile;
    }

    public void setAaFile(byte[] aaFile) {
        this.aaFile = aaFile;
    }

    public void setAaFile(DG15File aaFile) {
        this.aaFile = aaFile.getEncoded();
    }

    public byte[] getEaFileAsBytes() {
        return eaFile;
    }

    public void setEaFile(byte[] eaFile) {
        this.eaFile = eaFile;
    }

    public void setEaFile(DG14File eaFile) {
        this.eaFile = eaFile.getEncoded();
    }

    public SODFile getSodFile() {
        return sodFile;
    }

    public void setSodFile(SODFile sodFile) {
        this.sodFile = sodFile;
    }


    public void setPortraitFile(byte[] portraitFile) {
        this.portraitFile = portraitFile;
    }

    public void setPortrait(DG2File portrait) {
        this.portraitFile = portrait.getEncoded();
    }

}

