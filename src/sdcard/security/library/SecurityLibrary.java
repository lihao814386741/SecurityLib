package sdcard.security.library;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;





import iaik.asn1.ASN;
import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.DerCoder;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.pkcs.PKCSException;
import iaik.pkcs.PKCSParsingException;
import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509AttributeCertificate;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs7.DigestInfo;
import iaik.pkcs.pkcs7.EncryptedContentInfoStream;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.security.provider.IAIK;
import iaik.utils.RFC2253NameParser;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;

public class SecurityLibrary  {

	private Token token = null;
	private Slot slot = null;
	private Slot[] slots = null;
	private Session session = null;
	private Info info = null;
	private Module pkcs11Module = null;
	static public AlgorithmID algorithmID;
	static public PKCS11Constants pkcsConstants;
	
	public String getName(){
		return "Test:String";
	}

	public void initialize() throws IOException, TokenException{
		pkcs11Module = Module.getInstance("pkcs11wrapper");
		pkcs11Module.initialize(new DefaultInitializeArgs());
		
		Security.addProvider(new IAIK());

		slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
		
		Slot selectedSlot = slots[0];
		
		Token token = selectedSlot.getToken();
		TokenInfo tokenInfo = token.getTokenInfo();
		
		this.slot = selectedSlot;
		this.token = token;
	}
	
	public void finalize(){
		
		try {
//			if(token==null)
//				System.out.println("token is null");
//			else
//				System.out.println("token is not null");
			session.closeSession();
			pkcs11Module.finalize(null);
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean login(boolean isNormalUser, String PIN) throws TokenException, IOException{
		String buffer = "";
		if (isNormalUser){
			session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION,
				    null, null);
			session.login(Session.UserType.USER, PIN.toCharArray());			
		}
		else {
			session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION,
				    null, null);
			session.login(Session.UserType.SO, PIN.toCharArray());		
		}
		
		if (session == null)
			return false;
		return true;
	}
	
	public String getPKCS11Info() throws TokenException{
		Info info = pkcs11Module.getInfo();
		return info.toString();
	}
	
	public String getSlotsInfo() {
		String slotsInfoStr = "";
		
		for (int i = 0; i < slots.length; i++) {
			slotsInfoStr += "________________________________________________________________________________\n";
			SlotInfo slotsInfo = null;
			try {
				slotsInfo = slots[i].getSlotInfo();
			} catch (TokenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			slotsInfoStr += "Slot with ID: \n";
			slotsInfoStr += slots[i].getSlotID();
			slotsInfoStr += "--------------------------------------------------------------------------------\n";
			slotsInfoStr += slotsInfo.toString();
			slotsInfoStr += "\n________________________________________________________________________________\n";
		}
		
		return slotsInfoStr;
	}
	
	public String getTokensInfo(){
		String tokenInfoStr = "";
		
		TokenInfo tokenInfo = null;
		try {
			tokenInfo = token.getTokenInfo();
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		tokenInfoStr += "Token in slot with ID: ";
		tokenInfoStr += token.getSlot().getSlotID();
		tokenInfoStr += "\n--------------------------------------------------------------------------------\n";
		tokenInfoStr += tokenInfo;

		return tokenInfoStr;
	}
	
	public String getSupportedMechanisms(){
		String supportedMechanismsStr = "";
		
		supportedMechanismsStr += "supported Mechanisms:\n";
		Mechanism[] supportedMechanisms = null;
		try {
			supportedMechanisms = token.getMechanismList();
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for (int j = 0; j < supportedMechanisms.length; j++) {
			supportedMechanismsStr += "--------------------------------------------------------------------------------\n";
			supportedMechanismsStr += "Mechanism Name: " + supportedMechanisms[j].getName();
			supportedMechanismsStr += '\n';
			MechanismInfo mechanismInfo = null;
			try {
				mechanismInfo = token.getMechanismInfo(supportedMechanisms[j]);
			} catch (TokenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			supportedMechanismsStr += '\n';
			supportedMechanismsStr += mechanismInfo;
			supportedMechanismsStr += "\n--------------------------------------------------------------------------------\n";
		}
		supportedMechanismsStr += "________________________________________________________________________________";
		
		return supportedMechanismsStr;
	}
	
	public String getSessionInfo(){
		String sessionInfoStr = "";
		
	    SessionInfo sessionInfo = null;
		try {
			sessionInfo = session.getSessionInfo();
		} catch (TokenException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
	    sessionInfoStr += " using session:";
	    sessionInfoStr += sessionInfo;

		int limit = 0, counter = 0;
		
		try {
			session.findObjectsInit(null);
		} catch (TokenException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		Object[] objects = null;
		try {
			objects = session.findObjects(1);
		} catch (TokenException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		if (0 < objects.length) counter++;
		
		CertificateFactory x509CertificateFactory = null;
		while (objects.length > 0 && (0 == limit || counter < limit)) {
			Object object = objects[0];
			sessionInfoStr += "\n--------------------------------------------------------------------------------\n";
			sessionInfoStr += "Object with handle: " + objects[0].getObjectHandle();
			sessionInfoStr += '\n';
			sessionInfoStr +=object.toString();
			if (object instanceof X509PublicKeyCertificate) {
				try {
					byte[] encodedCertificate = ((X509PublicKeyCertificate) object).getValue()
					    .getByteArrayValue();
					if (x509CertificateFactory == null) {
						x509CertificateFactory = CertificateFactory.getInstance("X.509");
					}
					Certificate certificate = x509CertificateFactory
					    .generateCertificate(new ByteArrayInputStream(encodedCertificate));
					sessionInfoStr +="................................................................................\n";
					sessionInfoStr += "The decoded X509PublicKeyCertificate is:\n";
					sessionInfoStr += certificate.toString();
					sessionInfoStr += "\n................................................................................\n";
				} catch (Exception ex) {
					sessionInfoStr += "Could not decode this X509PublicKeyCertificate. Exception is: "
					        + ex.toString();
					sessionInfoStr += '\n';
				}
			} else if (object instanceof X509AttributeCertificate) {
				try {
					byte[] encodedCertificate = ((X509AttributeCertificate) object).getValue()
					    .getByteArrayValue();
					if (x509CertificateFactory == null) {
						x509CertificateFactory = CertificateFactory.getInstance("X.509");
					}
					Certificate certificate = x509CertificateFactory
					    .generateCertificate(new ByteArrayInputStream(encodedCertificate));
					sessionInfoStr += "................................................................................\n";
					sessionInfoStr += "The decoded X509AttributeCertificate is:\n";
					sessionInfoStr += certificate.toString();

					sessionInfoStr += "\n................................................................................\n";
				} catch (Exception ex) {
					sessionInfoStr += "Could not decode this X509AttributeCertificate. Exception is: "
					        + ex.toString();
					sessionInfoStr += '\n';
				}
			}
			// test the (deep) cloning feature
			// Object clonedObject = (Object) object.clone();
			sessionInfoStr += "--------------------------------------------------------------------------------\n";
			try {
				objects = session.findObjects(1);
			} catch (TokenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			counter++;
		}
		try {
			session.findObjectsFinal();
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sessionInfoStr;
	}
	
	public Object generateEncryptKey(long algorithmid) throws TokenException{
		Mechanism keyMechanism = Mechanism.get(algorithmid);
		
		if (algorithmid == PKCS11Constants.CKM_DES3_KEY_GEN){
			DES3SecretKey secretKeyTemplate = new DES3SecretKey();
			secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
			return session.generateKey(keyMechanism, secretKeyTemplate);
		}
		else if (algorithmid == PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN){
			
				Mechanism keyGenerationMechanism = Mechanism
				    .get(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN);

				GenericSecretKey secretKeyTemplate = new GenericSecretKey();
				secretKeyTemplate.getValueLen().setLongValue(new Long(16));

				return  session.generateKey(keyGenerationMechanism, secretKeyTemplate);
		}
		else if (algorithmid == PKCS11Constants.CKM_DES_KEY_GEN){
			DESSecretKey secretKeyTemplate = new DESSecretKey();
			secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
			return session.generateKey(keyMechanism, secretKeyTemplate);
		}
		else if (algorithmid == PKCS11Constants.CKM_DES2_KEY_GEN){
			DES2SecretKey secretKeyTemplate = new DES2SecretKey();
			secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
			return session.generateKey(keyMechanism, secretKeyTemplate);
		}
		else if (algorithmid == PKCS11Constants.CKM_AES_KEY_GEN){
			AESSecretKey secretKeyTemplate = new AESSecretKey();
			secretKeyTemplate.getValueLen().setLongValue(new Long(16));
			secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
			return session.generateKey(keyMechanism, secretKeyTemplate);
		}
		
		return null;
	}
	
	public byte[] EncryptData(String inFilename, long algorithmid) throws TokenException, IOException{
		DES3SecretKey secretEncryptionKeyTemplate = null;
		if(algorithmid == PKCS11Constants.CKM_DES3_KEY_GEN){
			secretEncryptionKeyTemplate = new DES3SecretKey();
			secretEncryptionKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
			secretEncryptionKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
		} 
		
		session.findObjectsInit(secretEncryptionKeyTemplate);
		Object[] foundEncryptKeys = session.findObjects(1);
		session.findObjectsFinal();
		Key encryptionKey = (Key) foundEncryptKeys[0];
		
		InputStream dataInputStream = new FileInputStream(inFilename);
		
		byte[] dataBuffer = new byte[1024];
		int bytesRead;
		ByteArrayOutputStream streamBuffer = new ByteArrayOutputStream();

		System.out.println("Before");

		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			streamBuffer.write(dataBuffer, 0, bytesRead);
		}
		dataInputStream.close();
		System.out.println("After");

		Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory
		streamBuffer.flush();
		streamBuffer.close();
		byte[] rawData = streamBuffer.toByteArray();
		

		Mechanism encryptionMechanism = Mechanism.get(PKCS11Constants.CKM_DES3_CBC_PAD);
		byte[] encryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0 };
		InitializationVectorParameters encryptInitializationVectorParameters = new InitializationVectorParameters(
			    encryptInitializationVector);
		encryptionMechanism.setParameters(encryptInitializationVectorParameters);
		

		session.encryptInit(encryptionMechanism, encryptionKey);
		byte[] encryptedData = session.encrypt(rawData);
		return encryptedData;
	}
	
	public byte[] DectryptData(byte[] encryptedData) throws TokenException{
		
		DES3SecretKey secretEncryptionKeyTemplate = new DES3SecretKey();
		secretEncryptionKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		secretEncryptionKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
		
		session.findObjectsInit(secretEncryptionKeyTemplate);
		Object[] foundEncryptKeys = session.findObjects(1);
		session.findObjectsFinal();
		Key encryptionKey = (Key) foundEncryptKeys[0];
		
		Mechanism decryptionMechanism = Mechanism.get(PKCS11Constants.CKM_DES3_CBC_PAD);
		byte[] decryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0 };
		InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(
		    decryptInitializationVector);
		decryptionMechanism.setParameters(decryptInitializationVectorParameters);
		
		session.decryptInit(decryptionMechanism, encryptionKey);

		byte[] decryptedData = session.decrypt(encryptedData);
		
		return decryptedData;
	}
	
	public void uploadKeyAndCertificate(RSAPrivateKey privateKey, X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException, X509ExtensionInitException, TokenException{

		
		RSAPrivateKey jcaRsaPrivateKey = privateKey;
		
		X509Certificate userCertificate = certificate;
		String userCommonName = ((Name) userCertificate.getSubjectDN()).getRDN(
		    ObjectID.commonName).toString();
		byte[] certificateFingerprint = userCertificate.getFingerprint("SHA-1");
		KeyUsage keyUsage = (KeyUsage) userCertificate.getExtension(KeyUsage.oid);
		SubjectKeyIdentifier subjectKeyIdentifier = (SubjectKeyIdentifier) userCertificate
		    .getExtension(SubjectKeyIdentifier.oid);
		
		HashSet supportedMechanisms = new HashSet(Arrays.asList(token.getMechanismList()));
		
		MechanismInfo signatureMechanismInfo;
		if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_X_509));
		}else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS));
		}   else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_9796));
		} else if (supportedMechanisms.contains(Mechanism
		    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
		} else {
			signatureMechanismInfo = null;
		}
		
		// create private key object template
		RSAPrivateKey pkcs11RsaPrivateKey = new RSAPrivateKey();

//		pkcs11RsaPrivateKey.getAlwaysSensitive().setBooleanValue(Boolean.FALSE);
		pkcs11RsaPrivateKey.getExtractable().setBooleanValue(Boolean.TRUE);
		pkcs11RsaPrivateKey.getModifiable().setBooleanValue(Boolean.TRUE);
		pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
		
		
		pkcs11RsaPrivateKey.getSensitive().setBooleanValue(Boolean.TRUE);
		//pkcs11RsaPrivateKey.getExtractable().setBooleanValue(Boolean.FALSE);
		pkcs11RsaPrivateKey.getToken().setBooleanValue(Boolean.TRUE);
		pkcs11RsaPrivateKey.getPrivate().setBooleanValue(Boolean.TRUE);
		String keyLabel = userCommonName + "'s "
		    + ((Name) userCertificate.getIssuerDN()).getRDN(ObjectID.organization);
		pkcs11RsaPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());

		
		
		
		
		byte[] newObjectID;
		if (subjectKeyIdentifier != null) {
			// we take the key identifier from the certificate
			newObjectID = subjectKeyIdentifier.get();
		} else {
			// then we simply take the fingerprint of the certificate
			newObjectID = certificateFingerprint;
		}
		
		pkcs11RsaPrivateKey.getId().setByteArrayValue(newObjectID);

		//pkcs11RsaPrivateKey.getStartDate().setDateValue(userCertificate.getNotBefore());
		//pkcs11RsaPrivateKey.getEndDate().setDateValue(userCertificate.getNotAfter());

		pkcs11RsaPrivateKey.getSubject().setByteArrayValue(
		    ((Name) userCertificate.getSubjectDN()).getEncoded());
		
		if (keyUsage != null) {
			// set usage flags acording to key usage flags of certificate
			int keyUsageFlags = keyUsage.get();

			// set the attributes in a way netscape does, this should work with most tokens
			if (signatureMechanismInfo != null) {
				pkcs11RsaPrivateKey
				    .getDecrypt()
				    .setBooleanValue(
				        new Boolean(
				            (((keyUsageFlags & KeyUsage.dataEncipherment) != 0) || ((keyUsageFlags & KeyUsage.keyCertSign) != 0))
				                && signatureMechanismInfo.isDecrypt()));
				pkcs11RsaPrivateKey
				    .getSign()
				    .setBooleanValue(
				        new Boolean(
				            (((keyUsageFlags & KeyUsage.digitalSignature) != 0)
				                || ((keyUsageFlags & KeyUsage.keyCertSign) != 0)
				                || ((keyUsageFlags & KeyUsage.cRLSign) != 0) || ((keyUsageFlags & KeyUsage.nonRepudiation) != 0))
				                && signatureMechanismInfo.isSign()));
				pkcs11RsaPrivateKey
				    .getSignRecover()
				    .setBooleanValue(
				        new Boolean(
				            (((keyUsageFlags & KeyUsage.digitalSignature) != 0)
				                || ((keyUsageFlags & KeyUsage.keyCertSign) != 0)
				                || ((keyUsageFlags & KeyUsage.cRLSign) != 0) || ((keyUsageFlags & KeyUsage.nonRepudiation) != 0))
				                && signatureMechanismInfo.isSignRecover()));
				pkcs11RsaPrivateKey.getDerive().setBooleanValue(
				    new Boolean(((keyUsageFlags & KeyUsage.keyAgreement) != 0)
				        && signatureMechanismInfo.isDerive()));
//				pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
//				    new Boolean(((keyUsageFlags & KeyUsage.keyEncipherment) != 0)
//				        && signatureMechanismInfo.isUnwrap()));
			} else {
				// if we have no mechanism information, we try to set the flags according to the key usage only
				pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(
				    new Boolean(((keyUsageFlags & KeyUsage.dataEncipherment) != 0)
				        || ((keyUsageFlags & KeyUsage.keyCertSign) != 0)));
				pkcs11RsaPrivateKey.getSign().setBooleanValue(
				    new Boolean(((keyUsageFlags & KeyUsage.digitalSignature) != 0)
				        || ((keyUsageFlags & KeyUsage.keyCertSign) != 0)
				        || ((keyUsageFlags & KeyUsage.cRLSign) != 0)
				        || ((keyUsageFlags & KeyUsage.nonRepudiation) != 0)));
				pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(
				    new Boolean(((keyUsageFlags & KeyUsage.digitalSignature) != 0)
				        || ((keyUsageFlags & KeyUsage.keyCertSign) != 0)
				        || ((keyUsageFlags & KeyUsage.cRLSign) != 0)
				        || ((keyUsageFlags & KeyUsage.nonRepudiation) != 0)));
				pkcs11RsaPrivateKey.getDerive().setBooleanValue(
				    new Boolean((keyUsageFlags & KeyUsage.keyAgreement) != 0));
				pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
				    new Boolean((keyUsageFlags & KeyUsage.keyEncipherment) != 0));
			}
		} else {
			// if there is no keyusage extension in the certificate, try to set all flags according to the mechanism info
			if (signatureMechanismInfo != null) {
				pkcs11RsaPrivateKey.getSign().setBooleanValue(
				    new Boolean(signatureMechanismInfo.isSign()));
				pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(
				    new Boolean(signatureMechanismInfo.isSignRecover()));
				pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(
				    new Boolean(signatureMechanismInfo.isDecrypt()));
				pkcs11RsaPrivateKey.getDerive().setBooleanValue(
				    new Boolean(signatureMechanismInfo.isDerive()));
				pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
				    new Boolean(signatureMechanismInfo.isUnwrap()));
			} else {
				// if we have neither mechanism info nor key usage we just try all
				pkcs11RsaPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
				pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(Boolean.TRUE);
				pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(Boolean.TRUE);
				pkcs11RsaPrivateKey.getDerive().setBooleanValue(Boolean.TRUE);
				pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
			}
		}
		
		pkcs11RsaPrivateKey.getModulus().setByteArrayValue(jcaRsaPrivateKey
			        .getModulus().getByteArrayValue());
			pkcs11RsaPrivateKey.getPrivateExponent().setByteArrayValue(jcaRsaPrivateKey
			        .getPrivateExponent().getByteArrayValue());
			pkcs11RsaPrivateKey
			    .getPublicExponent()
			    .setByteArrayValue(
			        iaik.pkcs.pkcs11.Util
			            .unsignedBigIntergerToByteArray(((java.security.interfaces.RSAPublicKey) userCertificate
			                .getPublicKey()).getPublicExponent()));
			
//			if (jcaRsaPrivateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
//				// if we have the CRT field, we write it to the card
//				// e.g. gemsafe seems to need it
//				System.out.println("jcaRsaPrivateKey");
			//	RSAPrivateCrtKey crtKey =  jcaRsaPrivateKey;
				pkcs11RsaPrivateKey.getPrime1().setByteArrayValue(jcaRsaPrivateKey.getPrime1().getByteArrayValue());
				pkcs11RsaPrivateKey.getPrime2().setByteArrayValue(jcaRsaPrivateKey.getPrime2().getByteArrayValue());
				pkcs11RsaPrivateKey.getExponent1()
				    .setByteArrayValue(jcaRsaPrivateKey.getExponent1().getByteArrayValue());
				pkcs11RsaPrivateKey.getExponent2()
				    .setByteArrayValue(jcaRsaPrivateKey.getExponent2().getByteArrayValue());
				pkcs11RsaPrivateKey.getCoefficient()
				    .setByteArrayValue(jcaRsaPrivateKey.getCoefficient().getByteArrayValue());
//			}
//		pkcs11RsaPrivateKey.getAlwaysSensitive().setBooleanValue(Boolean.FALSE);
//		pkcs11RsaPrivateKey.getNeverExtractable().setBooleanValue(Boolean.FALSE);
	//	pkcs11RsaPrivateKey.getLocal().setBooleanValue(Boolean.FALSE);
		
			
		System.out.println("!!!!!!!!!!pkcs11RsaPrivateKey!!!!!!!!!!!");

		System.out.println(pkcs11RsaPrivateKey);
		System.out.println("!!!!!!!!!!END!!!!!!!!!!!");

		
		
		session.createObject(pkcs11RsaPrivateKey);
		
		
		X509PublicKeyCertificate pkcs11X509PublicKeyCertificate = new X509PublicKeyCertificate();

		pkcs11X509PublicKeyCertificate.getToken().setBooleanValue(Boolean.TRUE);
		pkcs11X509PublicKeyCertificate.getPrivate().setBooleanValue(Boolean.FALSE);
		pkcs11X509PublicKeyCertificate.getLabel().setCharArrayValue(keyLabel.toCharArray());
		pkcs11X509PublicKeyCertificate.getSubject().setByteArrayValue(
		    ((Name) userCertificate.getSubjectDN()).getEncoded());
		pkcs11X509PublicKeyCertificate.getId().setByteArrayValue(newObjectID);
		pkcs11X509PublicKeyCertificate.getIssuer().setByteArrayValue(
		    ((Name) userCertificate.getIssuerDN()).getEncoded());
		
		pkcs11X509PublicKeyCertificate.getSerialNumber().setByteArrayValue(
			    userCertificate.getSerialNumber().toByteArray());
			pkcs11X509PublicKeyCertificate.getValue().setByteArrayValue(
			    userCertificate.getEncoded());
		pkcs11X509PublicKeyCertificate.getModifiable().setBooleanValue(Boolean.TRUE);
		
		System.out.println("!!!!!!!!!!pkcs11X509PublicKeyCertificate!!!!!!!!!!!");
		System.out.println(pkcs11X509PublicKeyCertificate);
		System.out.println("!!!!!!!!!!END!!!!!!!!!!!");

		session.createObject(pkcs11X509PublicKeyCertificate);
	}
	
	public void generateSelfSignCertificate(String request) throws TokenException, NoSuchAlgorithmException, RFC2253NameParserException, InvalidKeyException, X509ExtensionException, CertificateException, FileNotFoundException{
		HashSet supportedMechanisms = new HashSet(Arrays.asList(token.getMechanismList()));
		
		MechanismInfo signatureMechanismInfo;
		
		if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_X_509));
			System.out.println("^^^^^^^^^^^^^^^^^^^^^CKM_RSA_X_509^^^^^^^^^^^^^^^^^^^^^^");
		}
		else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS));
		} else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_9796));
		} else if (supportedMechanisms.contains(Mechanism
		    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
			signatureMechanismInfo = token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
		} else {
			signatureMechanismInfo = null;
		}
		
		Mechanism keyPairGenerationMechanism = Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
		RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
		RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

		// set the general attributes for the public key
		rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(1024));
		byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
		rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
		rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		byte[] id = new byte[20];
		new Random().nextBytes(id);
		rsaPublicKeyTemplate.getId().setByteArrayValue(id);
		//rsaPublicKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());

		rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getId().setByteArrayValue(id);

		if (signatureMechanismInfo != null) {
			System.out.println("!!!!!!!!!!!!signatureMechanismInfo is in");
			rsaPublicKeyTemplate.getVerify().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerify()));
			rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerifyRecover()));
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isEncrypt()));
			rsaPublicKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPublicKeyTemplate.getWrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isWrap()));

			rsaPrivateKeyTemplate.getSign().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSign()));
			rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSignRecover()));
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDecrypt()));
			rsaPrivateKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isUnwrap()));
			//###################################################
		} else {
			// if we have no information we assume these attributes
			rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

			rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		}

		rsaPublicKeyTemplate.getKeyType().setPresent(false);
		rsaPublicKeyTemplate.getObjectClass().setPresent(false);

		rsaPrivateKeyTemplate.getKeyType().setPresent(false);
		rsaPrivateKeyTemplate.getObjectClass().setPresent(false);
		rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

		
		KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism,
			    rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
		RSAPublicKey generatedRSAPublicKey = (RSAPublicKey) generatedKeyPair.getPublicKey();
		RSAPrivateKey generatedRSAPrivateKey = (RSAPrivateKey) generatedKeyPair
			    .getPrivateKey();
		generatedRSAPrivateKey.getExtractable().setBooleanValue(Boolean.TRUE);
		
//		System.out.println("##########generatedRSAPrivateKey##########");
//		System.out.println(generatedRSAPrivateKey);
//		System.out.println("##########END##########");
//		System.out.println("##########generatedRSAPublicKey##########");
//		System.out.println(generatedRSAPublicKey);
//		System.out.println("##########END##########");
//		
		iaik.security.rsa.RSAPublicKey publicKey = new iaik.security.rsa.RSAPublicKey(new BigInteger(1, generatedRSAPublicKey.getModulus().getByteArrayValue()),
			    new BigInteger(1, generatedRSAPublicKey.getPublicExponent().getByteArrayValue()));
		RSAPrivateKey selectedSignatureKey = generatedRSAPrivateKey;
	//	RSAPublicKey publicKey = generatedRSAPublicKey;
		
	
		Signature tokenSignatureEngine = new PKCS11SignatureEngine("SHA1withRSA", session,  Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), AlgorithmID.sha1);
		
		AlgorithmIDAdapter pkcs11Sha1RSASignatureAlgorithmID = new AlgorithmIDAdapter(
			    AlgorithmID.sha1WithRSAEncryption);
		pkcs11Sha1RSASignatureAlgorithmID.setSignatureInstance(tokenSignatureEngine);
		
		RFC2253NameParser subjectNameParser = new RFC2253NameParser(request);
		Name subjectName = subjectNameParser.parse();

		X509Certificate certificate = new X509Certificate();				
		
		certificate.setSubjectDN(subjectName);
		certificate.setIssuerDN(subjectName);
		
		
		// set pulbic key
		certificate.setPublicKey(publicKey);

		// set serial number
		certificate.setSerialNumber(new BigInteger("1"));

		// set validity
		Calendar date = new GregorianCalendar();
		certificate.setValidNotBefore(date.getTime()); // valid from now
		date.add(Calendar.YEAR, 3);
		certificate.setValidNotAfter(date.getTime()); // for 3 years

		// set extensions
		V3Extension basicConstraints = new BasicConstraints(true);
		certificate.addExtension(basicConstraints);

		V3Extension keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign
		    | KeyUsage.digitalSignature);
		certificate.addExtension(keyUsage);

		PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(null, null,
		    "This certificate may be used for demonstration purposes only.");
		PolicyInformation policyInformation = new PolicyInformation(new ObjectID(
		    "1.3.6.1.4.1.2706.2.2.1.1.1.1.1"),
		    new PolicyQualifierInfo[] { policyQualifierInfo });
		CertificatePolicies certificatePolicies = new CertificatePolicies(
		    new PolicyInformation[] { policyInformation });
		V3Extension policies = certificatePolicies;
		certificate.addExtension(policies);
		
		java.security.PrivateKey tokenSignatureKey = new TokenPrivateKey(selectedSignatureKey);
		
		certificate.sign(pkcs11Sha1RSASignatureAlgorithmID, tokenSignatureKey);


		uploadKeyAndCertificate(generatedRSAPrivateKey, certificate);
		
		System.out.println(certificate);
		
	}
	
	public void generateKeyPair() throws TokenException{
		HashSet supportedMechanisms = new HashSet(Arrays.asList(this.token.getMechanismList()));
		
		MechanismInfo signatureMechanismInfo;
		
		if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_X_509));
		}
		else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS));
		} else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_9796));
		} else if (supportedMechanisms.contains(Mechanism
		    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
		} else {
			signatureMechanismInfo = null;
		}
		
		Mechanism keyPairGenerationMechanism = Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
		RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
		RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

		// set the general attributes for the public key
		rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(2048));
		byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
		rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
		rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		byte[] id = new byte[20];
		new Random().nextBytes(id);
		rsaPublicKeyTemplate.getId().setByteArrayValue(id);
		//rsaPublicKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());

//		rsaPrivateKeyTemplate.getAlwaysSensitive().setBooleanValue(Boolean.FALSE);
	//	rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
		
		rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getId().setByteArrayValue(id);

		if (signatureMechanismInfo != null) {
			System.out.println("*******signatureMechanismInfo is not null\n");
			rsaPublicKeyTemplate.getVerify().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerify()));
			rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerifyRecover()));
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isEncrypt()));
			rsaPublicKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPublicKeyTemplate.getWrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isWrap()));

			rsaPrivateKeyTemplate.getSign().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSign()));
			rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSignRecover()));
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDecrypt()));
			rsaPrivateKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isUnwrap()));
		} else {
			// if we have no information we assume these attributes
			rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

			rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		}

		rsaPublicKeyTemplate.getKeyType().setPresent(false);
		rsaPublicKeyTemplate.getObjectClass().setPresent(false);

		rsaPrivateKeyTemplate.getKeyType().setPresent(false);
		rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

		KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism,
			    rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
		RSAPublicKey generatedRSAPublicKey = (RSAPublicKey) generatedKeyPair.getPublicKey();
		RSAPrivateKey generatedRSAPrivateKey = (RSAPrivateKey) generatedKeyPair
			    .getPrivateKey();
		

		System.out.println("**********generatedKeyPair**********");
		System.out.println(generatedKeyPair.getPrivateKey());
		System.out.println("**********END**********");

		//this.session.createObject(generatedKeyPair.getPrivateKey());
		//this.session.createObject(generatedRSAPublicKey);
		System.out.println("OK");
	}
	
	public byte[] generateRadom(int size) throws TokenException{
		return session.generateRandom(size);
	}

	public byte[] generateDigest(long algorithmID, InputStream dataInputStream) throws TokenException, IOException{

		Mechanism digestMechanism = Mechanism.get(algorithmID);
		session.digestInit(digestMechanism);

		
		byte[] dataBuffer = new byte[1024];
		byte[] helpBuffer;
		int bytesRead;
		
		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for digesting
			System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
			session.digestUpdate(helpBuffer);
			Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
		}
		
		Arrays.fill(dataBuffer, (byte) 0);
		
		byte[] outputByte = session.digestFinal();
		
		DigestInfo digestInfo = new DigestInfo(AlgorithmID.sha1, outputByte);
		
		return  digestInfo.toByteArray();
	}
		
	public byte[] generateDigest(long algorithmID, byte[] dataByte) throws TokenException, IOException{

		Mechanism digestMechanism = Mechanism.get(algorithmID);
		session.digestInit(digestMechanism);

		byte[] outputByte = session.digest(dataByte);
		DigestInfo digestInfo = new DigestInfo(AlgorithmID.sha1, outputByte);
		return digestInfo.toByteArray();
	}

	public void generateDigest(long algorithmID, String dataFileName, String outputFileName) throws TokenException, IOException{
		FileInputStream dataInputStream = new FileInputStream(dataFileName);
		FileOutputStream outputStream = new FileOutputStream(outputFileName);
		

		Mechanism digestMechanism = Mechanism.get(algorithmID);
		session.digestInit(digestMechanism);

		
		
		byte[] dataBuffer = new byte[1024];
		byte[] helpBuffer;
		int bytesRead;
		
		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for digesting
			System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
			session.digestUpdate(helpBuffer);
			Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
		}
		
		Arrays.fill(dataBuffer, (byte) 0);
		
		byte[] outputByte = session.digestFinal();
		
		DigestInfo digestInfo = new DigestInfo(AlgorithmID.sha1, outputByte);

		outputStream.write(digestInfo.toByteArray());
	}

	
	public void PackedData(InputStream dataInputStream, OutputStream dataOutputStream) throws TokenException, IOException, CertificateException, CodingException, NoSuchAlgorithmException{
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		String output = "";
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		if (selectedSignatureKeyAndCertificate == null) {
			System.out.println( "We have no signature key to proceed. Finished.\n");
		} 
		else {
			System.out.println( "Found a suitable key\n");
		}
		
		PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
			    .getKey();
		X509PublicKeyCertificate pkcs11SignerCertificate = selectedSignatureKeyAndCertificate
			    .getCertificate();
		X509Certificate signerCertificate = (pkcs11SignerCertificate != null) ? new X509Certificate(
			    pkcs11SignerCertificate.getValue().getByteArrayValue()) : null;
			    
//				System.out.println(selectedSignatureKey);
//				System.out.println("##############END##############");
//				
//				System.out.println("##############pkcs11SignerCertificate##############");
//				System.out.println(pkcs11SignerCertificate);
//				System.out.println("##############END##############");
		
		MessageDigest digestEngine = MessageDigest.getInstance("SHA-1");
		
		ByteArrayOutputStream contentBuffer = new ByteArrayOutputStream();
		byte[] dataBuffer = new byte[1024];
		int bytesRead;
		
		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			// hash the data
			digestEngine.update(dataBuffer, 0, bytesRead);
			// and buffer the data
			contentBuffer.write(dataBuffer, 0, bytesRead);
		}	
//		byte[] contentHash = digestEngine.digest();
		contentBuffer.close();
		byte[] contentHash = this.generateDigest(PKCS11Constants.CKM_SHA_1, contentBuffer.toByteArray());
		
		SignedData signedData = new SignedData(contentBuffer.toByteArray(),
			    SignedData.IMPLICIT);
			// set the certificates
		signedData.setCertificates(new X509Certificate[] { signerCertificate });

			// create a new SignerInfo
		SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(signerCertificate),
			    AlgorithmID.sha1, null);
		
		Attribute[] authenticatedAttributes = {
			    new Attribute(ObjectID.contentType, new ASN1Object[] { ObjectID.pkcs7_data }),
			    new Attribute(ObjectID.signingTime,
			        new ASN1Object[] { new ChoiceOfTime().toASN1Object() }),
			    new Attribute(ObjectID.messageDigest, new ASN1Object[] { new OCTET_STRING(
			        contentHash) }) };

		signerInfo.setAuthenticatedAttributes(authenticatedAttributes);
		byte[] toBeSigned = DerCoder.encode(ASN.createSetOf(authenticatedAttributes, true));
		byte[] mergeString = contentBuffer.toByteArray();
		MessageDigest digestEngine2 = MessageDigest.getInstance("SHA-1");
		
		
		byte[] toBeSignedlast = new byte[toBeSigned.length + contentBuffer.toByteArray().length];
		
		for(int i=0; i<mergeString.length;++i)
			toBeSignedlast[i]=mergeString[i];
		
		for(int i=mergeString.length; i<toBeSignedlast.length; ++i){
			toBeSignedlast[i] = toBeSigned[i-mergeString.length];
		}
			
//		System.arraycopy(toBeSigned, 0, toBeSignedlast, 0, toBeSigned.length);
//		System.arraycopy(contentBuffer,0, toBeSignedlast,  toBeSigned.length, contentBuffer.size());
//		
//		System.out.println("toBeSignedlast");
//		for(int i=0; i<toBeSignedlast.length; ++i)
//			System.out.print(toBeSignedlast[i]);
//		System.out.println("");
		
//		byte[] hashToBeSigned = digestEngine.digest(toBeSigned);
		byte[] hashToBeSigned = this.generateDigest(PKCS11Constants.CKM_SHA_1, toBeSignedlast);
		
		
		

//		System.out.println("contentHash");
//		
//		for (int i = 0; i < contentHash.length; ++ i)
//				System.out.print(contentHash[i]);
//		
//		System.out.println("\nhashToBeSigned");
//		for (int i = 0; i < hashToBeSigned.length; ++ i)
//			System.out.print(hashToBeSigned[i]);
//		System.out.println();
//		
//		System.out.println("hashToBeSigned2");
//		for (int i = 0; i < hashToBeSigned2.length; ++ i)
//			System.out.print(hashToBeSigned2[i]);
//		System.out.println();

//		 according to PKCS#11 building the DigestInfo structure must be done off-card
		DigestInfo digestInfoEngine = new DigestInfo(AlgorithmID.sha1, hashToBeSigned);

		byte[] toBeEncrypted = digestInfoEngine.toByteArray();

		
//		for (int i = 0; i < toBeEncrypted.length; ++ i)
//			System.out.print(toBeEncrypted[i]);
//		System.out.println();
		
		
		// initialize for signing
		session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_X_509), selectedSignatureKey);

		// sign the data to be signed################################################
		byte[] signatureValue = session.sign(toBeEncrypted);
//		System.out.println("##############signedData  11##############");

		signerInfo.setEncryptedDigest(signatureValue);
//		
		signedData.addSignerInfo(signerInfo);
//		
//		System.out.println("##############signedData##############");
//		System.out.println(signedData);
//		System.out.println("##############END##############");
//
		signedData.writeTo(dataOutputStream);
	}
	
	public void PackedData(String inputFileName, String outputFileName) throws TokenException, IOException, CertificateException, CodingException, NoSuchAlgorithmException{
		InputStream dataInputStream = new FileInputStream(inputFileName);
		OutputStream dataOutputStream = new FileOutputStream(outputFileName);

		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		String output = "";
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		if (selectedSignatureKeyAndCertificate == null) {
			System.out.println( "We have no signature key to proceed. Finished.\n");
		} 
		else {
			System.out.println( "Found a suitable key\n");
		}
		
		PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
			    .getKey();
		X509PublicKeyCertificate pkcs11SignerCertificate = selectedSignatureKeyAndCertificate
			    .getCertificate();
		X509Certificate signerCertificate = (pkcs11SignerCertificate != null) ? new X509Certificate(
			    pkcs11SignerCertificate.getValue().getByteArrayValue()) : null;
			    
//				System.out.println(selectedSignatureKey);
//				System.out.println("##############END##############");
//				
//				System.out.println("##############pkcs11SignerCertificate##############");
//				System.out.println(pkcs11SignerCertificate);
//				System.out.println("##############END##############");
		
		MessageDigest digestEngine = MessageDigest.getInstance("SHA-1");
		
		ByteArrayOutputStream contentBuffer = new ByteArrayOutputStream();
		byte[] dataBuffer = new byte[1024];
		int bytesRead;
		
		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			// hash the data
			digestEngine.update(dataBuffer, 0, bytesRead);
			// and buffer the data
			contentBuffer.write(dataBuffer, 0, bytesRead);
		}	
//		byte[] contentHash = digestEngine.digest();
		contentBuffer.close();
		byte[] contentHash = this.generateDigest(PKCS11Constants.CKM_SHA_1, contentBuffer.toByteArray());
		
		SignedData signedData = new SignedData(contentBuffer.toByteArray(),
			    SignedData.IMPLICIT);
			// set the certificates
		signedData.setCertificates(new X509Certificate[] { signerCertificate });

			// create a new SignerInfo
		SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(signerCertificate),
			    AlgorithmID.sha1, null);
		
		Attribute[] authenticatedAttributes = {
			    new Attribute(ObjectID.contentType, new ASN1Object[] { ObjectID.pkcs7_data }),
			    new Attribute(ObjectID.signingTime,
			        new ASN1Object[] { new ChoiceOfTime().toASN1Object() }),
			    new Attribute(ObjectID.messageDigest, new ASN1Object[] { new OCTET_STRING(
			        contentHash) }) };

		signerInfo.setAuthenticatedAttributes(authenticatedAttributes);
		byte[] toBeSigned = DerCoder.encode(ASN.createSetOf(authenticatedAttributes, true));
		byte[] mergeString = contentBuffer.toByteArray();
		MessageDigest digestEngine2 = MessageDigest.getInstance("SHA-1");
		
		
		byte[] toBeSignedlast = new byte[toBeSigned.length + contentBuffer.toByteArray().length];
		
		for(int i=0; i<mergeString.length;++i)
			toBeSignedlast[i]=mergeString[i];
		
		for(int i=mergeString.length; i<toBeSignedlast.length; ++i){
			toBeSignedlast[i] = toBeSigned[i-mergeString.length];
		}
			
//		System.arraycopy(toBeSigned, 0, toBeSignedlast, 0, toBeSigned.length);
//		System.arraycopy(contentBuffer,0, toBeSignedlast,  toBeSigned.length, contentBuffer.size());
//		
//		System.out.println("toBeSignedlast");
//		for(int i=0; i<toBeSignedlast.length; ++i)
//			System.out.print(toBeSignedlast[i]);
//		System.out.println("");
		
		byte[] hashToBeSigned = digestEngine.digest(toBeSigned);
		byte[] hashToBeSigned2 = this.generateDigest(PKCS11Constants.CKM_SHA_1, toBeSignedlast);
		
		
		

		System.out.println("contentHash");
		
		for (int i = 0; i < contentHash.length; ++ i)
				System.out.print(contentHash[i]);
		
		System.out.println("\nhashToBeSigned");
		for (int i = 0; i < hashToBeSigned.length; ++ i)
			System.out.print(hashToBeSigned[i]);
		System.out.println();
		
		System.out.println("hashToBeSigned2");
		for (int i = 0; i < hashToBeSigned2.length; ++ i)
			System.out.print(hashToBeSigned2[i]);
		System.out.println();

//		 according to PKCS#11 building the DigestInfo structure must be done off-card
		DigestInfo digestInfoEngine = new DigestInfo(AlgorithmID.sha1, hashToBeSigned);

		byte[] toBeEncrypted = digestInfoEngine.toByteArray();

		
//		for (int i = 0; i < toBeEncrypted.length; ++ i)
//			System.out.print(toBeEncrypted[i]);
//		System.out.println();
		
		
		// initialize for signing
		session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_X_509), selectedSignatureKey);

		// sign the data to be signed################################################
		byte[] signatureValue = session.sign(toBeEncrypted);
//		System.out.println("##############signedData  11##############");

		signerInfo.setEncryptedDigest(signatureValue);
//		
		signedData.addSignerInfo(signerInfo);
//		
//		System.out.println("##############signedData##############");
//		System.out.println(signedData);
//		System.out.println("##############END##############");
//
		signedData.writeTo(dataOutputStream);
	}

	public void PackedDataTest(InputStream dataInputStream, OutputStream dataOutputStream, OutputStream testOutputStream) throws TokenException, IOException, CertificateException, CodingException, NoSuchAlgorithmException{
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		String output = "";
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		if (selectedSignatureKeyAndCertificate == null) {
			System.out.println( "We have no signature key to proceed. Finished.\n");
		} 
		else {
			System.out.println( "Found a suitable key\n");
		}
		
		PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
			    .getKey();
		X509PublicKeyCertificate pkcs11SignerCertificate = selectedSignatureKeyAndCertificate
			    .getCertificate();
		X509Certificate signerCertificate = (pkcs11SignerCertificate != null) ? new X509Certificate(
			    pkcs11SignerCertificate.getValue().getByteArrayValue()) : null;
			    
//				System.out.println(selectedSignatureKey);
//				System.out.println("##############END##############");
//				
//				System.out.println("##############pkcs11SignerCertificate##############");
//				System.out.println(pkcs11SignerCertificate);
//				System.out.println("##############END##############");
		
		MessageDigest digestEngine = MessageDigest.getInstance("SHA-1");
		
		ByteArrayOutputStream contentBuffer = new ByteArrayOutputStream();
		byte[] dataBuffer = new byte[1024];
		int bytesRead;
		
		while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
			// hash the data
			digestEngine.update(dataBuffer, 0, bytesRead);
			// and buffer the data
			contentBuffer.write(dataBuffer, 0, bytesRead);
		}	
//		byte[] contentHash = digestEngine.digest();
		contentBuffer.close();
		byte[] contentHash = this.generateDigest(PKCS11Constants.CKM_SHA_1, contentBuffer.toByteArray());
		
		SignedData signedData = new SignedData(contentBuffer.toByteArray(),
			    SignedData.IMPLICIT);
		SignedData signedData1 = new SignedData(contentBuffer.toByteArray(),
			    SignedData.IMPLICIT);
			// set the certificates
		signedData.setCertificates(new X509Certificate[] { signerCertificate });
		signedData1.setCertificates(new X509Certificate[] { signerCertificate });

			// create a new SignerInfo
		SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(signerCertificate),
			    AlgorithmID.sha1, null);
		SignerInfo signerInfo1 = new SignerInfo(new IssuerAndSerialNumber(signerCertificate),
			    AlgorithmID.sha1, null);
		
		Attribute[] authenticatedAttributes = {
			    new Attribute(ObjectID.contentType, new ASN1Object[] { ObjectID.pkcs7_data }),
			    new Attribute(ObjectID.signingTime,
			        new ASN1Object[] { new ChoiceOfTime().toASN1Object() }),
			    new Attribute(ObjectID.messageDigest, new ASN1Object[] { new OCTET_STRING(
			        contentHash) }) };

		signerInfo.setAuthenticatedAttributes(authenticatedAttributes);
		signerInfo1.setAuthenticatedAttributes(authenticatedAttributes);

		byte[] toBeSigned = DerCoder.encode(ASN.createSetOf(authenticatedAttributes, true));
		byte[] mergeString = contentBuffer.toByteArray();
		MessageDigest digestEngine2 = MessageDigest.getInstance("SHA-1");
		
		
		byte[] toBeSignedlast = new byte[toBeSigned.length + contentBuffer.toByteArray().length];
		
		for(int i=0; i<mergeString.length;++i)
			toBeSignedlast[i]=mergeString[i];
		
		for(int i=mergeString.length; i<toBeSignedlast.length; ++i){
			toBeSignedlast[i] = toBeSigned[i-mergeString.length];
		}
			
		byte[] hashToBeSigned = this.generateDigest(PKCS11Constants.CKM_SHA_1, toBeSignedlast);
		
		
		
		
		

		DigestInfo digestInfoEngine = new DigestInfo(AlgorithmID.sha1, hashToBeSigned);

		byte[] toBeEncrypted = digestInfoEngine.toByteArray();

		
		
		session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_X_509), selectedSignatureKey);

		byte[] signatureValue = session.sign(toBeEncrypted);
		byte[] signatureValue1 = this.signData(toBeEncrypted);


		signerInfo.setEncryptedDigest(signatureValue);
		signerInfo1.setEncryptedDigest(signatureValue1);

		signedData.addSignerInfo(signerInfo);
		signedData1.addSignerInfo(signerInfo1);

		
		signedData.writeTo(dataOutputStream);
		signedData1.writeTo(testOutputStream);
	}


	/*	这里的algorithmID支持以下几个对称加密算法：
	 * AlgorithmID.aes128_CBC;
	 * AlgorithmID.aes192_CBC;
	 * AlgorithmID.aes256_CBC;
	 * AlgorithmID.des_CBC;
	 * AlgorithmID.des_EDE3_CBC;
	 * 
	 * */
	
	public byte[] EncryptEnvelopeData(AlgorithmID algorithmID, byte[] inBuf,  byte[] certBuf) throws NoSuchAlgorithmException, CertificateException, IOException
	{

		InputStream dataInputStream = new ByteArrayInputStream(inBuf);
		InputStream certificateInputStream = new ByteArrayInputStream(certBuf);
		ByteArrayOutputStream envelopedDataOutputStream=new ByteArrayOutputStream();

		
		EnvelopedDataStream envelopedData = new EnvelopedDataStream(dataInputStream,
				algorithmID);
		
		
		X509Certificate recipientCertificate = new X509Certificate(certificateInputStream);
		
	//	System.out.println(recipientCertificate.toString(true));
		
		RecipientInfo recipient = new RecipientInfo(recipientCertificate,
			    AlgorithmID.rsaEncryption);
		
		envelopedData.setRecipientInfos(new RecipientInfo[] { recipient });

		
		envelopedData.writeTo(envelopedDataOutputStream);
		return envelopedDataOutputStream.toByteArray();
		
//		envelopedDataOutputStream.write(outBuf);
		
//		outBuf = envelopedDataOutputStream.toByteArray();
//		
//		for (int i = 0; i < outBuf.length; ++ i)
//			System.out.print(outBuf[i]);
//		System.out.println();
		
	}
	
	public void EncryptEnvelopeStream(AlgorithmID algorithmID,InputStream dataInputStream, InputStream certificateInputStream, OutputStream envelopedDataOutputStream) throws NoSuchAlgorithmException, CertificateException, IOException
	{

		
		EnvelopedDataStream envelopedData = new EnvelopedDataStream(dataInputStream,
			    algorithmID);

		
		X509Certificate recipientCertificate = new X509Certificate(certificateInputStream);
		
	//	System.out.println(recipientCertificate.toString(true));
		
		RecipientInfo recipient = new RecipientInfo(recipientCertificate,
			    AlgorithmID.rsaEncryption);
		
		envelopedData.setRecipientInfos(new RecipientInfo[] { recipient });

		
		envelopedData.writeTo(envelopedDataOutputStream);
//		outBuf = envelopedDataOutputStream.toByteArray();
	}
	
	public void EncryptEnvelopeFile(AlgorithmID algorithmID, String inputFileName, String certFileName, String outputFileName) throws NoSuchAlgorithmException, CertificateException, IOException
	{
		InputStream dataInputStream = new FileInputStream(inputFileName);
		InputStream certInputStream = new FileInputStream(certFileName);
		OutputStream outputStream = new FileOutputStream(outputFileName);
		
		
		
		EnvelopedDataStream envelopedData = new EnvelopedDataStream(dataInputStream,
			    algorithmID);

		
		X509Certificate recipientCertificate = new X509Certificate(certInputStream);
		
	//	System.out.println(recipientCertificate.toString(true));
		
		RecipientInfo recipient = new RecipientInfo(recipientCertificate,
			    AlgorithmID.rsaEncryption);
		
		envelopedData.setRecipientInfos(new RecipientInfo[] { recipient });

		
		envelopedData.writeTo(outputStream);
	}

	public void DecryptEnvelopeStream(FileInputStream encryptedInputStream, OutputStream decryptedContentStream) throws IOException, TokenException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, PKCSException
	{
		List tokenCertificates = new Vector();
		X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
		session.findObjectsInit(certificateTemplate);
		Object[] tokenCertificateObjects;
		
		while ((tokenCertificateObjects = session.findObjects(1)).length > 0) {
			tokenCertificates.add(tokenCertificateObjects[0]);
		}
		session.findObjectsFinal();

		EnvelopedDataStream envelopedData = new EnvelopedDataStream(encryptedInputStream);
		RecipientInfo[] recipientInfos = envelopedData.getRecipientInfos();
		
		boolean haveDecryptionKey = false;
		InputStream decryptedDataInputStream = null;
		
		System.out.println(recipientInfos.length);


		for (int i = 0; i < recipientInfos.length; i++) {
			IssuerAndSerialNumber issuerAndSerialNumber = recipientInfos[i]
			    .getIssuerAndSerialNumber();

			// look if there is a certificate on our token with the given issuer and serial number
			X509PublicKeyCertificate matchingTokenCertificate = null;
			Iterator tokenCertificatesIterator = tokenCertificates.iterator();
			while (tokenCertificatesIterator.hasNext()) {
				X509PublicKeyCertificate tokenCertificate = (X509PublicKeyCertificate) tokenCertificatesIterator
				    .next();
				X509Certificate parsedTokenCertificate = new X509Certificate(tokenCertificate
				    .getValue().getByteArrayValue());
				if (issuerAndSerialNumber.isIssuerOf(parsedTokenCertificate)) {
					matchingTokenCertificate = tokenCertificate;
					break;
				}
			}

			System.out.println("matchingTokenCertificate is : " + matchingTokenCertificate);

			
			if (matchingTokenCertificate != null) {
				// find the corresponding private key for the certificate
				PrivateKey privateKeyTemplate = new PrivateKey();
				privateKeyTemplate.getId().setByteArrayValue(
				    matchingTokenCertificate.getId().getByteArrayValue());

				session.findObjectsInit(privateKeyTemplate);
				Object[] correspondingPrivateKeyObjects;
				PrivateKey correspondingPrivateKey = null;

				if ((correspondingPrivateKeyObjects = session.findObjects(1)).length > 0) {
					correspondingPrivateKey = (PrivateKey) correspondingPrivateKeyObjects[0];
				} else {
					System.out.println("Found no private key with the same ID as the matching certificate.");
				}
				session.findObjectsFinal();

				// check, if the private key is a decrpytion key
				PrivateKey decryptionKey = ((correspondingPrivateKey != null) && (correspondingPrivateKey
				    .getDecrypt().getBooleanValue().booleanValue())) ? correspondingPrivateKey
				    : null;
				
				System.out.println("!!!!!!!!!!!!!correspondingPrivateKey is : " + correspondingPrivateKey);

				if (decryptionKey != null) {
					haveDecryptionKey = true;
					byte[] encryptedSymmetricKey = recipientInfos[i].getEncryptedKey();
					// decrypt the encrypted symmetric key using the e.g. RSA on the smart-card
					
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey is");
					for (int j = 0; j < encryptedSymmetricKey.length; ++ j)
					{
						System.out.print(encryptedSymmetricKey[j]);

					}						
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey end " + encryptedSymmetricKey.length);

					System.out.flush();
					
					session.decryptInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), decryptionKey);
					byte[] decryptedSymmetricKey = session.decrypt(encryptedSymmetricKey);
					
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey is");
					for (int j = 0; j < decryptedSymmetricKey.length; ++ j)
					{
						System.out.print(decryptedSymmetricKey[j]);

					}
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey end");

					// construct the symmetric key
					EncryptedContentInfoStream encryptedContentInfo = (EncryptedContentInfoStream) envelopedData
					    .getEncryptedContentInfo();
					AlgorithmID contentEncryptionAlgorithm = encryptedContentInfo
					    .getContentEncryptionAlgorithm();
					SecretKeyFactory secretKeyFactory = SecretKeyFactory
					    .getInstance(contentEncryptionAlgorithm.getRawImplementationName());

					javax.crypto.SecretKey secretKey;
					if (contentEncryptionAlgorithm.getRawImplementationName().equalsIgnoreCase(
					    "DESede")) {
						/*
						 * we now that the content encryption algorithm is DES3 if we run our EncryptPKCS7EnvelopedData-test
						 * to generate the data. Providing the appropriate keyspec is necessary for JKDs < 1.6. For JDKs >= 1.6
						 * the else path works as well for DES keys.
						 */
						DESedeKeySpec secretKeySpec = new DESedeKeySpec(decryptedSymmetricKey);
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					} else {
						SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedSymmetricKey,
						    contentEncryptionAlgorithm.getRawImplementationName());
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					}
					RecipientInfo[] reinfo = envelopedData.getRecipientInfos();
					
					System.out.println("!!!!!!!!!!!!!reinfo is : " + reinfo);

					// decrypt the data (in software)
					encryptedContentInfo.setupCipher(secretKey);
					
					decryptedDataInputStream = encryptedContentInfo.getInputStream();

					// read decrypted data from decryptedDataInputStream
				}
			}
		}

		byte[] buffer = new byte[1024];
		int bytesRead;
		
		System.out.println("decryptedDataInputStream is : " + decryptedDataInputStream);
		
		while ((bytesRead = decryptedDataInputStream.read(buffer)) > 0) {					
			if (decryptedContentStream != null) {
				decryptedContentStream.write(buffer, 0, bytesRead);
			}
		}
		
		if (decryptedContentStream != null) {
			decryptedContentStream.flush();
			decryptedContentStream.close();
		}
		
		
		
	}
	
	public void DecryptEnvelopeFile(String inputFileName, String outputFileName) throws IOException, TokenException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, PKCSException
	{
		FileInputStream encryptedInputStream = new FileInputStream(inputFileName); 
		OutputStream decryptedContentStream = new FileOutputStream(outputFileName);
		
		List tokenCertificates = new Vector();
		X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
		session.findObjectsInit(certificateTemplate);
		Object[] tokenCertificateObjects;
		
		while ((tokenCertificateObjects = session.findObjects(1)).length > 0) {
			tokenCertificates.add(tokenCertificateObjects[0]);
		}
		session.findObjectsFinal();

		
		EnvelopedDataStream envelopedData = new EnvelopedDataStream(encryptedInputStream);
		RecipientInfo[] recipientInfos = envelopedData.getRecipientInfos();
		
		boolean haveDecryptionKey = false;
		InputStream decryptedDataInputStream = null;
		
		System.out.println(recipientInfos.length);


		for (int i = 0; i < recipientInfos.length; i++) {
			IssuerAndSerialNumber issuerAndSerialNumber = recipientInfos[i]
			    .getIssuerAndSerialNumber();

			// look if there is a certificate on our token with the given issuer and serial number
			X509PublicKeyCertificate matchingTokenCertificate = null;
			Iterator tokenCertificatesIterator = tokenCertificates.iterator();
			while (tokenCertificatesIterator.hasNext()) {
				X509PublicKeyCertificate tokenCertificate = (X509PublicKeyCertificate) tokenCertificatesIterator
				    .next();
				X509Certificate parsedTokenCertificate = new X509Certificate(tokenCertificate
				    .getValue().getByteArrayValue());
				if (issuerAndSerialNumber.isIssuerOf(parsedTokenCertificate)) {
					matchingTokenCertificate = tokenCertificate;
					break;
				}
			}

			System.out.println("matchingTokenCertificate is : " + matchingTokenCertificate);

			
			if (matchingTokenCertificate != null) {
				// find the corresponding private key for the certificate
				PrivateKey privateKeyTemplate = new PrivateKey();
				privateKeyTemplate.getId().setByteArrayValue(
				    matchingTokenCertificate.getId().getByteArrayValue());

				session.findObjectsInit(privateKeyTemplate);
				Object[] correspondingPrivateKeyObjects;
				PrivateKey correspondingPrivateKey = null;

				if ((correspondingPrivateKeyObjects = session.findObjects(1)).length > 0) {
					correspondingPrivateKey = (PrivateKey) correspondingPrivateKeyObjects[0];
				} else {
					System.out.println("Found no private key with the same ID as the matching certificate.");
				}
				session.findObjectsFinal();

				// check, if the private key is a decrpytion key
				PrivateKey decryptionKey = ((correspondingPrivateKey != null) && (correspondingPrivateKey
				    .getDecrypt().getBooleanValue().booleanValue())) ? correspondingPrivateKey
				    : null;
				
				System.out.println("!!!!!!!!!!!!!correspondingPrivateKey is : " + correspondingPrivateKey);

				if (decryptionKey != null) {
					haveDecryptionKey = true;
					byte[] encryptedSymmetricKey = recipientInfos[i].getEncryptedKey();
					// decrypt the encrypted symmetric key using the e.g. RSA on the smart-card
					
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey is");
					for (int j = 0; j < encryptedSymmetricKey.length; ++ j)
					{
						System.out.print(encryptedSymmetricKey[j]);
					}						
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey end " + encryptedSymmetricKey.length);

					System.out.flush();
					
					session.decryptInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), decryptionKey);
					byte[] decryptedSymmetricKey = session.decrypt(encryptedSymmetricKey);
					
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey is");
					for (int j = 0; j < decryptedSymmetricKey.length; ++ j)
					{
						System.out.print(decryptedSymmetricKey[j]);

					}
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey end");

					// construct the symmetric key
					EncryptedContentInfoStream encryptedContentInfo = (EncryptedContentInfoStream) envelopedData
					    .getEncryptedContentInfo();
					AlgorithmID contentEncryptionAlgorithm = encryptedContentInfo
					    .getContentEncryptionAlgorithm();
					SecretKeyFactory secretKeyFactory = SecretKeyFactory
					    .getInstance(contentEncryptionAlgorithm.getRawImplementationName());

					javax.crypto.SecretKey secretKey;
					if (contentEncryptionAlgorithm.getRawImplementationName().equalsIgnoreCase(
					    "DESede")) {
						/*
						 * we now that the content encryption algorithm is DES3 if we run our EncryptPKCS7EnvelopedData-test
						 * to generate the data. Providing the appropriate keyspec is necessary for JKDs < 1.6. For JDKs >= 1.6
						 * the else path works as well for DES keys.
						 */
						DESedeKeySpec secretKeySpec = new DESedeKeySpec(decryptedSymmetricKey);
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					} else {
						SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedSymmetricKey,
						    contentEncryptionAlgorithm.getRawImplementationName());
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					}
					RecipientInfo[] reinfo = envelopedData.getRecipientInfos();
					
					System.out.println("!!!!!!!!!!!!!reinfo is : " + reinfo);

					// decrypt the data (in software)
					encryptedContentInfo.setupCipher(secretKey);
					
					decryptedDataInputStream = encryptedContentInfo.getInputStream();

					// read decrypted data from decryptedDataInputStream
				}
			}
		}

		byte[] buffer = new byte[1024];
		int bytesRead;
		
		System.out.println("decryptedDataInputStream is : " + decryptedDataInputStream);
		
		while ((bytesRead = decryptedDataInputStream.read(buffer)) > 0) {					
			if (decryptedContentStream != null) {
				decryptedContentStream.write(buffer, 0, bytesRead);
			}
		}
		
		if (decryptedContentStream != null) {
			decryptedContentStream.flush();
			decryptedContentStream.close();
		}
		
		
		
	}
	
	public byte[] DecryptEnvelopeData(byte[] inBuf) throws IOException, TokenException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, PKCSException
	{

		InputStream encryptedInputStream = new ByteArrayInputStream(inBuf);
		ByteArrayOutputStream decryptedContentStream=new ByteArrayOutputStream();

		List tokenCertificates = new Vector();
		X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
		session.findObjectsInit(certificateTemplate);
		Object[] tokenCertificateObjects;
		
		while ((tokenCertificateObjects = session.findObjects(1)).length > 0) {
			tokenCertificates.add(tokenCertificateObjects[0]);
		}
		session.findObjectsFinal();

		EnvelopedDataStream envelopedData = new EnvelopedDataStream(encryptedInputStream);
		RecipientInfo[] recipientInfos = envelopedData.getRecipientInfos();
		
		boolean haveDecryptionKey = false;
		InputStream decryptedDataInputStream = null;
		
		System.out.println(recipientInfos.length);


		for (int i = 0; i < recipientInfos.length; i++) {
			IssuerAndSerialNumber issuerAndSerialNumber = recipientInfos[i]
			    .getIssuerAndSerialNumber();

			// look if there is a certificate on our token with the given issuer and serial number
			X509PublicKeyCertificate matchingTokenCertificate = null;
			Iterator tokenCertificatesIterator = tokenCertificates.iterator();
			while (tokenCertificatesIterator.hasNext()) {
				X509PublicKeyCertificate tokenCertificate = (X509PublicKeyCertificate) tokenCertificatesIterator
				    .next();
				X509Certificate parsedTokenCertificate = new X509Certificate(tokenCertificate
				    .getValue().getByteArrayValue());
				if (issuerAndSerialNumber.isIssuerOf(parsedTokenCertificate)) {
					matchingTokenCertificate = tokenCertificate;
					break;
				}
			}

			System.out.println("matchingTokenCertificate is : " + matchingTokenCertificate);

			
			if (matchingTokenCertificate != null) {
				// find the corresponding private key for the certificate
				PrivateKey privateKeyTemplate = new PrivateKey();
				privateKeyTemplate.getId().setByteArrayValue(
				    matchingTokenCertificate.getId().getByteArrayValue());

				session.findObjectsInit(privateKeyTemplate);
				Object[] correspondingPrivateKeyObjects;
				PrivateKey correspondingPrivateKey = null;

				if ((correspondingPrivateKeyObjects = session.findObjects(1)).length > 0) {
					correspondingPrivateKey = (PrivateKey) correspondingPrivateKeyObjects[0];
				} else {
					System.out.println("Found no private key with the same ID as the matching certificate.");
				}
				session.findObjectsFinal();

				// check, if the private key is a decrpytion key
				PrivateKey decryptionKey = ((correspondingPrivateKey != null) && (correspondingPrivateKey
				    .getDecrypt().getBooleanValue().booleanValue())) ? correspondingPrivateKey
				    : null;
				
				System.out.println("!!!!!!!!!!!!!correspondingPrivateKey is : " + correspondingPrivateKey);

				if (decryptionKey != null) {
					haveDecryptionKey = true;
					byte[] encryptedSymmetricKey = recipientInfos[i].getEncryptedKey();
					// decrypt the encrypted symmetric key using the e.g. RSA on the smart-card
					
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey is");
					for (int j = 0; j < encryptedSymmetricKey.length; ++ j)
					{
						System.out.print(encryptedSymmetricKey[j]);

					}						
					System.out.println("!!!!!!!!!!!!encryptedSymmetricKey end " + encryptedSymmetricKey.length);

					System.out.flush();
					
					session.decryptInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), decryptionKey);
					byte[] decryptedSymmetricKey = session.decrypt(encryptedSymmetricKey);
					
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey is");
					for (int j = 0; j < decryptedSymmetricKey.length; ++ j)
					{
						System.out.print(decryptedSymmetricKey[j]);

					}
					System.out.println("!!!!!!!!!!!!decryptedSymmetricKey end");

					// construct the symmetric key
					EncryptedContentInfoStream encryptedContentInfo = (EncryptedContentInfoStream) envelopedData
					    .getEncryptedContentInfo();
					AlgorithmID contentEncryptionAlgorithm = encryptedContentInfo
					    .getContentEncryptionAlgorithm();
					SecretKeyFactory secretKeyFactory = SecretKeyFactory
					    .getInstance(contentEncryptionAlgorithm.getRawImplementationName());

					javax.crypto.SecretKey secretKey;
					if (contentEncryptionAlgorithm.getRawImplementationName().equalsIgnoreCase(
					    "DESede")) {
						/*
						 * we now that the content encryption algorithm is DES3 if we run our EncryptPKCS7EnvelopedData-test
						 * to generate the data. Providing the appropriate keyspec is necessary for JKDs < 1.6. For JDKs >= 1.6
						 * the else path works as well for DES keys.
						 */
						DESedeKeySpec secretKeySpec = new DESedeKeySpec(decryptedSymmetricKey);
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					} else {
						SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedSymmetricKey,
						    contentEncryptionAlgorithm.getRawImplementationName());
						secretKey = secretKeyFactory.generateSecret(secretKeySpec);
					}
					RecipientInfo[] reinfo = envelopedData.getRecipientInfos();
					
					System.out.println("!!!!!!!!!!!!!reinfo is : " + reinfo);

					// decrypt the data (in software)
					encryptedContentInfo.setupCipher(secretKey);
					
					decryptedDataInputStream = encryptedContentInfo.getInputStream();

					// read decrypted data from decryptedDataInputStream
				}
			}
		}

		byte[] buffer = new byte[1024];
		int bytesRead;
		
		
		
		
		System.out.println("decryptedDataInputStream is : " + decryptedDataInputStream);
		
		while ((bytesRead = decryptedDataInputStream.read(buffer)) > 0) {					
			if (decryptedContentStream != null) {
				decryptedContentStream.write(buffer, 0, bytesRead);
			}
		}
		
		if (decryptedContentStream != null) {
			decryptedContentStream.flush();
			decryptedContentStream.close();
		}
		
		return decryptedContentStream.toByteArray();
	}

	public byte[] DepackedData(InputStream dataInput) throws PKCSParsingException, IOException{
			
			
			SignedDataStream signedData = new SignedDataStream(dataInput);
			InputStream contentStream = signedData.getInputStream();
			
			
			byte[] buffer = new byte[contentStream.available()];
			contentStream.read(buffer);
			
//			System.out.write(buffer, 0, buffer.length);
			return	buffer; 
	}
	
	public byte[] DepackedData(String fileName) throws PKCSParsingException, IOException{
		 
		InputStream dataInput = new FileInputStream(fileName);
		SignedDataStream signedData = new SignedDataStream(dataInput);
		InputStream contentStream = signedData.getInputStream();
		
		
		byte[] buffer = new byte[contentStream.available()];
		contentStream.read(buffer);
		
//		System.out.write(buffer, 0, buffer.length);
		return	buffer; 
	}
	
	
	public void createObject() throws TokenException{
		HashSet supportedMechanisms = new HashSet(Arrays.asList(this.token.getMechanismList()));
		
		MechanismInfo signatureMechanismInfo;
		
		if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_X_509));
		}
		else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS));
		} else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_9796));
		} else if (supportedMechanisms.contains(Mechanism
		    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
			signatureMechanismInfo = this.token.getMechanismInfo(Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
		} else {
			signatureMechanismInfo = null;
		}
		
		Mechanism keyPairGenerationMechanism = Mechanism
			    .get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
		RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
		RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

		// set the general attributes for the public key
		rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(2048));
		byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
		rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
		rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		byte[] id = new byte[20];
		new Random().nextBytes(id);
		rsaPublicKeyTemplate.getId().setByteArrayValue(id);
		//rsaPublicKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());

//		rsaPrivateKeyTemplate.getAlwaysSensitive().setBooleanValue(Boolean.FALSE);
	//	rsaPrivateKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
		
		rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
		rsaPrivateKeyTemplate.getId().setByteArrayValue(id);

		if (signatureMechanismInfo != null) {
			System.out.println("*******signatureMechanismInfo is not null\n");
			rsaPublicKeyTemplate.getVerify().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerify()));
			rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerifyRecover()));
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isEncrypt()));
			rsaPublicKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPublicKeyTemplate.getWrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isWrap()));

			rsaPrivateKeyTemplate.getSign().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSign()));
			rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isSignRecover()));
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDecrypt()));
			rsaPrivateKeyTemplate.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
			rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isUnwrap()));
		} else {
			// if we have no information we assume these attributes
			rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
			rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

			rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
			rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
		}

		rsaPublicKeyTemplate.getKeyType().setPresent(false);
		rsaPublicKeyTemplate.getObjectClass().setPresent(false);

		rsaPrivateKeyTemplate.getKeyType().setPresent(false);
		rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

		KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism,
			    rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
		RSAPublicKey generatedRSAPublicKey = (RSAPublicKey) generatedKeyPair.getPublicKey();
		RSAPrivateKey generatedRSAPrivateKey = (RSAPrivateKey) generatedKeyPair
			    .getPrivateKey();
		

		System.out.println("**********generatedKeyPair**********");
	//	System.out.println(generatedKeyPair.getPublicKey());
		System.out.println("**********END**********");

		
		RSAPublicKey exportRsaPublicKeyTemplate = new RSAPublicKey();
		exportRsaPublicKeyTemplate.getId().setByteArrayValue(id);

		session.findObjectsInit(exportRsaPublicKeyTemplate);
		Object[] foundPublicKeys = session.findObjects(1);
		session.findObjectsFinal();
		
		if (foundPublicKeys.length != 1) {
			System.out.println("Error: Cannot find the public key under the given ID!");
		} else {
			System.out.println("Found public key!");
			System.out.println("_______________________________________________________________________________");
			System.out.println(foundPublicKeys[0]);
			System.out.println("_______________________________________________________________________________");
		}

		
		
	}
	
	
	
	public byte[] signData(byte[] toBeEncrypted) throws TokenException, IOException{
		
		String output = "";
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		if (selectedSignatureKeyAndCertificate == null) {
			System.out.println( "We have no signature key to proceed. Finished.\n");
		} 
		else {
			System.out.println( "Found a suitable key\n");
		}
		
		PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
			    .getKey();
		
		session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), selectedSignatureKey);

		return session.sign(toBeEncrypted);
	}
	
	public void signFile(long algorithmId, String inputFileName, String outputFileName) throws TokenException, IOException{
		
		FileInputStream decryptedContentStream = new FileInputStream(inputFileName);
		FileOutputStream outputStream = new FileOutputStream(outputFileName);
		
		byte[] toBeEncrypted = new byte[decryptedContentStream.available()];
		
		decryptedContentStream.read(toBeEncrypted);

		
		
		String output = "";
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

		
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		if (selectedSignatureKeyAndCertificate == null) {
			System.out.println( "We have no signature key to proceed. Finished.\n");
		} 
		else {
			System.out.println( "Found a suitable key\n");
		}
		
		PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
			    .getKey();
		
		session.signInit(Mechanism.get(algorithmId), selectedSignatureKey);

		byte[] outputByte = session.sign(toBeEncrypted);
		
		outputStream.write(outputByte);
	}

	public boolean verifySignFile(long algorithmId, String dataFileName,String digestFileName, String signFileName, String certFileName) 
			throws IOException, CertificateException, NoSuchProviderException, InvalidKeyException, 
			SignatureException, NoSuchAlgorithmException, TokenException{
		
		FileInputStream dataInput = new FileInputStream(dataFileName);
		FileInputStream signInput = new FileInputStream(signFileName);
		FileInputStream digestInput = new FileInputStream(digestFileName);
		
		byte[] signature = new byte[signInput.available()];
		byte[] digestInfo = new byte[digestInput.available()];
		
		signInput.read(signature);
		digestInput.read(digestInfo);
		
		RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
		privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
		String output = "";
		
		FileInputStream certificateInput = new FileInputStream(certFileName);
		
		
		KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
			    session, privateSignatureKeyTemplate, output, "", true);
		
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",
		    "IAIK");
		//    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		
		byte[] encodedCertificate = selectedSignatureKeyAndCertificate.getCertificate()
			    .getValue().getByteArrayValue();
		X509Certificate certificate = (X509Certificate) certificateFactory
			    .generateCertificate(new ByteArrayInputStream(encodedCertificate));

		
		
		Signature verifyEngine;

		verifyEngine = Signature.getInstance("SHA1withRSA");
		
		
		verifyEngine.initVerify(certificate.getPublicKey());
		
		byte[] buffer = new byte[1024];
		int bytesRead;

		while ((bytesRead = dataInput.read(buffer, 0, buffer.length)) >= 0) {
			verifyEngine.update(buffer, 0, bytesRead);
		}

		
		if (verifyEngine.verify(signature)) {
			System.out.println("Verified signature successfully.");
			//return true;
		} else {
			System.out.println("Signature is INVALID.");
			//return false;
		}
		
		//************************************************************
		System.out.println("find public verification key");
		java.security.PublicKey publicKey = certificate.getPublicKey();
		
		java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
		
		BigInteger modulus = new BigInteger(1, rsaPublicKey.getModulus().toByteArray());
		BigInteger publicExponent = new BigInteger(1, rsaPublicKey.getPublicExponent().toByteArray());
		RSAPublicKey verificationKey = new RSAPublicKey();
		
		byte[] modulusBytes = iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(modulus);
		
		verificationKey.getModulus().setByteArrayValue(modulusBytes);
		verificationKey.getPublicExponent().setByteArrayValue(iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(publicExponent));
//		byte[] id = new byte[20];
//		new Random().nextBytes(id);
//		
//		verificationKey.getModulusBits().setLongValue((long) modulusBytes.length*8);
////		verificationKey.getModulusBits().setLongValue(new Long(2048));
//
		verificationKey.getToken().setBooleanValue(Boolean.TRUE);
//		
		MechanismInfo signatureMechanismInfo;
			signatureMechanismInfo = token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS));
			
		verificationKey.getVerify().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerify()));
		verificationKey.getVerifyRecover().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isVerifyRecover()));
		verificationKey.getEncrypt().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isEncrypt()));
		verificationKey.getDerive().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isDerive()));
		verificationKey.getWrap().setBooleanValue(
			    new Boolean(signatureMechanismInfo.isWrap()));
//			
		byte[] id = new byte[20];
		new Random().nextBytes(id);
//		char[] label1 = "ZZZZZZZZZZZZZZLIHAOZZZZZZZZZZZZZZZZ".toCharArray();
		
		verificationKey.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
		verificationKey.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
		verificationKey.getWrap().setBooleanValue(Boolean.TRUE);
		verificationKey.getEncrypt().setBooleanValue(Boolean.TRUE);
		verificationKey.getVerify().setBooleanValue(Boolean.TRUE);
		
//		verificationKey.getLabel().setCharArrayValue(label);
//		
		verificationKey.getModifiable().setBooleanValue(Boolean.TRUE);
		verificationKey.getPrivate().setBooleanValue(Boolean.FALSE);
//		verificationKey.getLocal().setBooleanValue(Boolean.TRUE);
//		verificationKey.getObjectClass().setPresent(true);
////		
//		verificationKey.getStartDate().setDateValue(null);
//		verificationKey.getEndDate() .setDateValue(null);
//		verificationKey.getSubject().setByteArrayValue(null);
//		
		verificationKey.getId().setByteArrayValue(id);
		
		
		
		System.out.println(verificationKey);
		
		session.createObject(verificationKey);
		System.out.println("Create Successful");
		
		
		RSAPublicKey exportRsaPublicKeyTemplate = new RSAPublicKey();
		exportRsaPublicKeyTemplate.getKeyType().setLongValue(PKCS11Constants.CKK_RSA);
//		exportRsaPublicKeyTemplate.getId().setByteArrayValue(id);
//
		session.findObjectsInit(exportRsaPublicKeyTemplate);
		Object[] foundPublicKeys = session.findObjects(1);
		session.findObjectsFinal();
//
		if (foundPublicKeys.length != 1) {
			System.out.println("Error: Cannot find the public key under the given ID!");
		} else {
			System.out.println("Found public key!");
			System.out
			    .println("_______________________________________________________________________________");
			System.out.println(foundPublicKeys[0]);
			System.out
			    .println("_______________________________________________________________________________");
		}
		verificationKey = (RSAPublicKey)foundPublicKeys[0];
		
		
		Mechanism verificationMechanism = Mechanism.get(algorithmId);
		
		// initialize for signing
		session.verifyInit(verificationMechanism, verificationKey);

		try {
			session.verify(digestInfo, signature); // throws an exception upon unsuccessful verification
			System.out.println("Verified the signature successfully");
			return true;
		} catch (TokenException ex) {
			System.out.println("Verification FAILED: " + ex.getMessage());
			return false;
		}
		
	}
		
	public Boolean VerifyPackedData(InputStream dataInput){
		
		
		try {
			
			
			SignedDataStream signedData = new SignedDataStream(dataInput);
			InputStream contentStream = signedData.getInputStream();
			
			
			byte[] buffer = new byte[1024];
			int bytesRead;
			
			
			System.out.println("The signed content data is: ");
			
			while ((bytesRead = contentStream.read(buffer)) > 0) {
				System.out.write(buffer, 0, bytesRead);
			}
			
			SignerInfo[] signerInfos = signedData.getSignerInfos();
			
			for (int i = 0; i < signerInfos.length; i++) {
				try {
					// verify the signature for SignerInfo at index i
					X509Certificate signerCertificate = signedData.verify(i);
					System.out.println("!!!Verify");
					byte[] sigedDigest = signedData.getSignedDigest(i);

				} catch (SignatureException ex) {
					// if the signature is not OK a SignatureException is thrown
					return false;
				}
			}
			
			
			
			
		} catch (IOException e) {
			return false;
		}  catch (Exception e) {
			return false;
		}
		
		return true;
	}
		
	
	public String logout(){
		try {
			session.logout();
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "Logout Failed.";
		}
		return "Logout Succeed.";
	}
	
	public String changeUserPIN(String oldPIN, String newPIN, String confirmedNewPIN){
		if (!newPIN.equals(confirmedNewPIN)) {
			return "The two entries do not match. Try again.";
		} else {
			try {
				session.setPIN(oldPIN.toCharArray(), newPIN.toCharArray());
			} catch (TokenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return "Change User's PIN Failed.";
			}
			return "Change User's PIN Succeed.";
		}
	}
	
	public String resetDevicePin(String newPIN){
		try {
			session.initPIN(newPIN.toCharArray());
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "Reset Device PIN Failed.";
		}
		return "Reset Device PIN Succeed.";
	}
	
}
