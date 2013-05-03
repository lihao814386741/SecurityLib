package com.example.test;

import iaik.asn1.CodingException;
import iaik.pkcs.PKCSException;
import iaik.pkcs.PKCSParsingException;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509ExtensionException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;


import sdcard.security.library.SecurityLibrary;
import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;

public class MainActivity extends Activity {

	
	public SecurityLibrary security;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		    security  = new SecurityLibrary();
	        
	        try {
	        
	        	
//#############################init###############################################
				security.initialize();
//#############################init###############################################

//#############################login###############################################
				security.login(true, "88888888");// USER
//				security.login(false, "12345678"); // SO
//#############################login###############################################

//#############################ChangePIN###############################################
//				security.changeUserPIN("11111111", "88888888", "88888888");///Success
//				security.resetDevicePin("88888888");
//				security.logout();
//				if(security.login(true, "88888888"))
//					System.out.println("resetSuccess");
//				security.logout();
//#############################ChangePIN###############################################

				
//#############################logout###############################################
//				security.logout();  //Success
//#############################logout###############################################

				
		
				
//#############################getInfo###############################################
//				System.out.println("getPKCS11Info");
//				System.out.println(security.getPKCS11Info());
//				System.out.println("getSessionInfo");
//				System.out.println(security.getSessionInfo());
//				System.out.println("getSlotsInfo");
//				System.out.println(security.getSlotsInfo());
//				System.out.println("getTokensInfo");
//				System.out.println(security.getTokensInfo());
//				System.out.println("GETSUPPORTEDMECHANISMS");
//				System.out.println(security.getSupportedMechanisms());
//#############################getInfo###############################################

//#############################generateRadom###############################################
//				byte[] radom = security.generateRadom(255);
//				
//				
//				for (int i = 0; i < radom.length; ++ i)
//					System.out.print(radom[i]);
//				System.out.println();
//#############################generateRadom###############################################
	
	
//#############################EncryptEnvelopeData###############################################
//				InputStream dataInputStream = new FileInputStream("/sdcard/packed.p7");
//				InputStream certInputStream = new FileInputStream("/sdcard/server.der");
//				OutputStream outputStream = new FileOutputStream("/sdcard/env_sl_backup.p7");
//				
//				try {
//					security.EncryptEnvelopeStream(dataInputStream, certInputStream, outputStream);
//				} catch (NoSuchAlgorithmException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (CertificateException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//#############################EncryptEnvelopeData###############################################
				
//#############################EncryptEnvelopeStream###############################################
//				InputStream dataInputStream = new FileInputStream("/sdcard/packed.p7");
//				InputStream certInputStream = new FileInputStream("/sdcard/server.der");
//				OutputStream outputStream   = new FileOutputStream("/sdcard/env_sl.p7");
//				
//				
//				
//				byte[] inBuf = new byte[dataInputStream.available()];
//				byte[] certBuf = new byte[certInputStream.available()];
//				
//				dataInputStream.read(inBuf);
//				certInputStream.read(certBuf);
//				
//				try {
//					byte[] outBuf = security.EncryptEnvelopeData(security.algorithmID.aes128_CBC, inBuf, certBuf);
//					
//					for (int i = 0; i < outBuf.length; ++ i)
//							System.out.print(outBuf[i]);
//					System.out.println();
//					outputStream.write(outBuf);
//				} catch (NoSuchAlgorithmException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (CertificateException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//				
//#############################EncryptEnvelopeStream###############################################

//#############################EncryptEnvelopeStream###############################################
//
//				try {
//					security.EncryptEnvelopeFile(security.algorithmID.aes128_CBC, "/sdcard/packed.p7", "/sdcard/server.der", "/sdcard/env_sl_file.p7");
//				} catch (NoSuchAlgorithmException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (CertificateException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//				
//				
//#############################EncryptEnvelopeStream###############################################
				
				
				
				
//#############################DecryptEnvelopeStream###############################################
//				FileInputStream encryptedInputStream = new FileInputStream("/sdcard/env_sl_file.p7");
//				OutputStream decryptedContentStream =  new FileOutputStream("/sdcard/decryptedContent_sl.dat");
//				
//				try {
//					try {
//						security.DecryptEnvelopeData(encryptedInputStream, decryptedContentStream);
//					} catch (CertificateException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (NoSuchAlgorithmException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
//				} catch (InvalidKeyException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (InvalidKeySpecException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (PKCSException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//#############################DecryptEnvelopeStream###############################################
		
//#############################DecryptEnvelopeFile###############################################
////				FileInputStream encryptedInputStream = new FileInputStream("/sdcard/env_sl_file.p7");
////				OutputStream decryptedContentStream =  new FileOutputStream("/sdcard/decryptedContent_sl.dat");
//				
//				try {
//					try {
//						security.DecryptEnvelopeFile("/sdcard/env_sl_file.p7", "/sdcard/decryptedContent_sl.dat");
//					} catch (CertificateException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (NoSuchAlgorithmException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
//				} catch (InvalidKeyException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (InvalidKeySpecException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (PKCSException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//#############################DecryptEnvelopeFile###############################################

				
//#############################DecryptEnvelopeData###############################################
//				FileInputStream encryptedInputStream = new FileInputStream("/sdcard/env_sl_file.p7");
//				OutputStream decryptedContentStream =  new FileOutputStream("/sdcard/decryptedContent_sl_data.dat");
//				byte[] inBuf = new byte[encryptedInputStream.available()];
//				
//				encryptedInputStream.read(inBuf);
//				
//				
//				try {
//					try {
//						byte[] outBuf = security.DecryptEnvelopeData(inBuf);
//						
//						for (int i = 0; i < outBuf.length; ++ i)
//							System.out.print(outBuf[i]);
//						System.out.println();
//						decryptedContentStream.write(outBuf);
//
//					} catch (CertificateException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (NoSuchAlgorithmException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
//				} catch (InvalidKeyException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (InvalidKeySpecException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (PKCSException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//#############################DecryptEnvelopeData###############################################
				
				
//#############################VerifyPackedData###############################################
//				FileInputStream decryptedContentStream = new FileInputStream("/sdcard/packed.p7");
//				if (security.VerifyPackedData(decryptedContentStream))
//						System.out.println("OK");
//				else System.out.println("FALSE");
//#############################VerifyPackedData###############################################
		
				
//#############################generateSelfSignCertificate###############################################	
//				try {
//					security.generateSelfSignCertificate("CN=LIHAO,O=PKU,C=AT,EMAIL=12334@5678.com");
//				} catch (InvalidKeyException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (X509ExtensionException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (RFC2253NameParserException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//#############################generateSelfSignCertificate###############################################	

				
				//security.signFile("/sdcard/small.txt", "/sdcard/packed_test.p7");
				
				
//				security.createObject();

				
				//this.testPackp7FileName();
				
				//this.testVerify();
				
				GenericSecretKey desObject = (GenericSecretKey)security.generateEncryptKey(security.pkcsConstants.CKM_GENERIC_SECRET_KEY_GEN);
				
				
				System.out.println(desObject);
				//this.testEnDecrypt();
				
				
				security.finalize();

				//System.out.println(text);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (TokenException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
	        
	}

	public void testDepackedFile(){
		
		byte[] output;
		try {
			output = security.DepackedData("/sdcard/packed.p7");
			System.out.write(output, 0, output.length);

		} catch (PKCSParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void testPackp7File() throws TokenException, IOException{
		
	//#############################generatePackedData###############################################
		InputStream dataInputStream = new FileInputStream("/sdcard/hosts.txt");
		OutputStream dataOutputStream = new FileOutputStream("/sdcard/packed.p7");
		System.out.println("1234567890-");
		try {
			try {
				security.PackedData(dataInputStream, dataOutputStream);
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (CodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void testPackp7FileName() throws CertificateException, NoSuchAlgorithmException, TokenException, IOException, CodingException{
		security.PackedData("/sdcard/hosts.txt", "/sdcard/packed.p7");
	}
	
	public void testDepacked() throws PKCSParsingException, IOException{
		
		FileInputStream decryptedContentStream = new FileInputStream("/sdcard/packed.p7");
		FileOutputStream outputStream = new FileOutputStream("/sdcard/depacked_test.p7");

		byte[] output = security.DepackedData(decryptedContentStream);
		
		System.out.write(output, 0, output.length);
		
	}
	
	
	/*
	 * 测试生成摘要的程序，满足两种算法CKM_MD5和CKM_SHA_1
	 * */
	public void testDigest() throws TokenException, IOException{
		InputStream dataInputStream = new FileInputStream("/sdcard/hosts.txt");
		byte[] digest = security.generateDigest(security.pkcsConstants.CKM_MD5, dataInputStream);
		String print = "The hash value #1 is: " + new BigInteger(1, digest).toString(16) + "\n";
		System.out.println(print);
	}
	public void testDigestByte() throws TokenException, IOException{
		InputStream dataInputStream = new FileInputStream("/sdcard/hosts.txt");
		byte[] inputByte = new byte[dataInputStream.available()];
		
		dataInputStream.read(inputByte);
		
		
		byte[] digest = security.generateDigest(security.pkcsConstants.CKM_MD5, inputByte);
		String print = "The hash value #1 is: " + new BigInteger(1, digest).toString(16) + "\n";
		System.out.println(print);
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
//		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	
	public void testSignData(){
		
		try {
			InputStream dataInputStream = new FileInputStream("/sdcard/hosts.txt");
			OutputStream dataOutputStream = new FileOutputStream("/sdcard/packed.p7");
			OutputStream testOutputStream = new FileOutputStream("/sdcard/packed_test.p7");

			System.out.println("1234567890-");
			try {
				try {
					security.PackedDataTest(dataInputStream, dataOutputStream, testOutputStream);
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (CodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TokenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void testVerify() throws TokenException, IOException{
		
		security.generateDigest(security.pkcsConstants.CKM_MD5, "/sdcard/hosts.txt", "/sdcard/hosts_digest");
		
		security.signFile(security.pkcsConstants.CKM_RSA_X_509, "/sdcard/hosts_digest", "/sdcard/hosts_digest_sigh");
		
		/*
		 * 支持签名算法：
		 * CKM_SHA1_RSA_PKCS
		 * CKM_RSA_PKCS
		 * CKM_RSA_X_509
		 * CKM_MD5_RSA_PKCS
		 * */

		
		try {
			security.verifySignFile(security.pkcsConstants.CKM_RSA_X_509, "/sdcard/hosts.txt", "/sdcard/hosts_digest", "/sdcard/hosts_digest_sigh", "/sdcard/server.der");
			
			
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void testEnDecrypt() throws TokenException, IOException{
		String inFilename = "/sdcard/hosts.txt";
		
//		security.generateEncryptKey();
//		
//		security.EncryptData(inFilename);
		
	}
}
