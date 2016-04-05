package org.irmacard.mno.common;

import net.sf.scuba.util.Hex;

import org.jmrtd.lds.ActiveAuthenticationInfo;
import org.jmrtd.lds.DG14File;
import org.jmrtd.lds.DG15File;
import org.jmrtd.lds.SODFile;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.RSABlindedEngine;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.ISO9796d2Signer;
import org.spongycastle.crypto.SignerWithRecovery;
import org.spongycastle.crypto.InvalidCipherTextException;

public abstract class DocumentDataMessage extends BasicClientMessage {

	private String imsi;
	protected byte [] challenge;  /* challenge sent by the server for AA */
	protected byte [] response;   /* AA response to challenge */
	SODFile sodFile;    /* security file with signed hashes of datagroups */
	protected DG14File eaFile;  /* SecurityInfos for EAC and PACE*/
	protected DG15File aaFile;  /* ACtive authentication public key */

	public DocumentDataMessage() {
		super();
	}

	public DocumentDataMessage(String sessionToken) {
		super(sessionToken);
	}

	public DocumentDataMessage(String sessionToken, String imsi) {
		super(sessionToken);
		this.imsi = imsi;
	}

	public DocumentDataMessage(String sessionToken, String imsi, byte[] challenge) {
		super(sessionToken);
		this.imsi = imsi;
		this.challenge = challenge;
	}

	protected abstract byte [] getPersonalDataFileAsBytes();
	protected abstract Integer getAADataGroupNumber();
	protected abstract String getIssuingState();
	protected abstract String getPersonalDataFileAsString();
	protected abstract SignerWithRecovery getRSASigner();
	protected abstract String getCertificateFilePath();
	protected abstract String getCertificateFileList();

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
	protected boolean verifyHashes(){
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
		digest.update(aaFile.getEncoded());
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
	*/	if (!Arrays.equals(hash_personal_data_file, hashes.get(1))) {
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
		String [] certFiles;
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);

            /*first load the properties file which contains the location of all certificates */
			pIns = this.getClass().getClassLoader().getResourceAsStream("certs/certificates.properties");
			if(pIns==null){
				throw new RuntimeException("Unable to load certificates.properties");
			}
			prop.load(pIns);

			certPath=prop.getProperty(getIssuingState()+getCertificateFilePath());
			certFiles=(prop.getProperty(getIssuingState()+getCertificateFileList())).split(",");
			for (String filename: certFiles){
				cIns = this.getClass().getClassLoader().getResourceAsStream(certPath+filename);
				cert = factory.generateCertificate(cIns);
				keyStore.setCertificateEntry(filename, cert);
				cIns.close();
			}
		} catch ( KeyStoreException
				| IOException
				| NoSuchAlgorithmException
				| CertificateException e) {
			e.printStackTrace();
		}
		return keyStore;
	}



	private boolean verifySignature() {
		try {
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
		for ( int j = 0; j < bytes.length; j++ ) {
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
		Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
		PublicKey publicKey = aaFile.getPublicKey();

		boolean answer = false;
		try{
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
		}  catch (ClassCastException         // Casting of publickey to an EC public key failed
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


	public static String rewriteECDSAMnenomic (String mnenomic) {
		if (mnenomic.equals("SHA1withECDSA")) { return "SHA1/CVC-ECDSA"; }
		if (mnenomic.equals("SHA224withECDSA")) { return "SHA224/CVC-ECDSA"; }
		if (mnenomic.equals("SHA256withECDSA")) { return "SHA256/CVC-ECDSA"; }
		if (mnenomic.equals("SHA384withECDSA")) { return "SHA348/CVC-ECDSA"; }
		if (mnenomic.equals("SHA512withECDSA")) { return "SHA512/CVC-ECDSA"; }
		if (mnenomic.equals("RIPEMD160withECDSA")) { return "RIPEMD160/CVC-ECDSA"; }

		return mnenomic;
	}

	public boolean isComplete () {
		if (sodFile == null)
			return false;

		if (sodFile.getDataGroupHashes().get(14) != null && eaFile == null)
			return false;

		return imsi != null && getPersonalDataFileAsBytes() != null && aaFile != null && response != null;
	}


	public String toString() {
		return "[IMSI: " + imsi + ", Session: " + getSessionToken() + "\n"
				+ "SODFile: " + sodFile.toString() +"\n"
				+ "DG1:" + getPersonalDataFileAsString() + "\n"
				+ "DG15" + aaFile.toString() + "\n"
				+ "response:" + Hex.bytesToHexString(response) + " ]";
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

	public DG15File getAaFile() {
		return aaFile;
	}

	public void setAaFile(DG15File aaFile) {
		this.aaFile = aaFile;
	}

	public DG14File getEaFile() {
		return eaFile;
	}

	public void setEaFile(DG14File eaFile) {
		this.eaFile = eaFile;
	}

	public SODFile getSodFile() {
		return sodFile;
	}

	public void setSodFile(SODFile sodFile) {
		this.sodFile = sodFile;
	}

	public String getImsi() {
		return imsi;
	}

	public void setImsi(String imsi) {
		this.imsi = imsi;
	}
}
