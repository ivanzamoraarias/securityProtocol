import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.SealedObject;
import javax.crypto.Cipher;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;


public class simetricTest {

	 static String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
	    static char[] passPherase = "secretpass".toCharArray();
	    static byte[] salt = "a9v5n38s".getBytes();
	    static String secretData = "Very Secret Data!!";
	    
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		 try{
	            Security.addProvider(new BouncyCastleProvider());
	            SealedObject encryptedString = encrypt(secretData);
	            String decryptedString = decrypt(encryptedString);
	            System.out.println(decryptedString);
	        }catch( Exception e ) { 
	            System.out.println(e.toString());
	        }

	}
	
	static SealedObject encrypt(String data) throws Exception{
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt,20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(passPherase);
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(algorithm);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.ENCRYPT_MODE,secretKey,pbeParamSpec);
	    //System.out.println(secretKey.);

	    return new SealedObject(data,cipher);
	}
	
	static String decrypt(SealedObject sealedObject) throws Exception{
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt,20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(passPherase);
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(algorithm);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.DECRYPT_MODE,secretKey,pbeParamSpec);
	    return (String)sealedObject.getObject(cipher);
	}
	

	
}
