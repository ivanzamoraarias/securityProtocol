import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import sun.misc.BASE64Decoder;

public class RSAsignature {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    
	    Signature signature = Signature.getInstance("SHA1withRSA", "BC");
	    Signature.getInstance("RSA");

	    //haciendo la firma
	    PrivateKey privK= getPrivateKey("privatefileA.txt");
	
	    signature.initSign(privK, new SecureRandom());

	    byte[] message = "abc".getBytes();
	    signature.update(message);
	    
	    //verificacion
	    PublicKey pubK= getPublicKey("publicfileA.txt");
	    byte[] sigBytes = signature.sign();
	    signature.initVerify(pubK);
	    signature.update(message);
	    System.out.println(signature.verify(sigBytes));
	   
	    
	}
	 public static PrivateKey getPrivateKey(String filename)
			  throws Exception {

		 BASE64Decoder b64 = new BASE64Decoder();
         String key = readFileAsString(filename);
         
			    KeyFactory kf = KeyFactory.getInstance("RSA","BC");
			   
			    PKCS8EncodedKeySpec spec =
			    	      new PKCS8EncodedKeySpec(b64.decodeBuffer(key));
			    return kf.generatePrivate(spec);
			  }
	 
	 private static String readFileAsString(String filePath)
			    throws java.io.IOException{
			        StringBuffer fileData = new StringBuffer(1000);
			        BufferedReader reader = new BufferedReader(
			                new FileReader(filePath));
			        char[] buf = new char[1024];
			        int numRead=0;
			        while((numRead=reader.read(buf)) != -1){
			            String readData = String.valueOf(buf, 0, numRead);
			            fileData.append(readData);
			            buf = new char[1024];
			        }
			        reader.close();
			        //System.out.println(fileData.toString());
			        return fileData.toString();
			    }
			
	 public static PublicKey getPublicKey(String filename)
			    throws Exception {

		 BASE64Decoder b64 = new BASE64Decoder();
         String key = readFileAsString(filename);
         
			    KeyFactory kf = KeyFactory.getInstance("RSA","BC");
			
			    X509EncodedKeySpec spec =
			    	      new X509EncodedKeySpec(b64.decodeBuffer(key));
			    return kf.generatePublic(spec);
				  }
	 public static PublicKey getPublicKeyFromString(String str) throws Exception
	 {
		 BASE64Decoder b64 = new BASE64Decoder();
		 String key =str;
		 KeyFactory kf = KeyFactory.getInstance("RSA","BC");
			
		    X509EncodedKeySpec spec =
		    	      new X509EncodedKeySpec(b64.decodeBuffer(key));
		    return kf.generatePublic(spec);
	 }

}
