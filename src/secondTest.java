import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;


public class secondTest {

	public final static int pValue = 47;
	public final static int gValue = 71;
	public final static int XaValue = 9;
	public final static int XbValue = 14;
	 
	public static void main(String[] args) throws Exception {
		BigInteger p = new BigInteger(Integer.toString(pValue));
	    BigInteger g = new BigInteger(Integer.toString(gValue));
	    BigInteger Xa = new BigInteger(Integer.toString(XaValue));
	    BigInteger Xb = new BigInteger(Integer.toString(XbValue));
	    
	    int bitLength = 512; // 512 bits
	    SecureRandom rnd = new SecureRandom();
	    p = BigInteger.probablePrime(bitLength, rnd);
	    g = BigInteger.probablePrime(bitLength, rnd);
	    
	    
	    String derivadaW="wertyuio";
	    byte[] sw=derivadaW.getBytes();
	    String derivadaKDC="m,./;lkj";
	    byte[] skdc=derivadaKDC.getBytes();
	    String clavedeUsuario= "/Gvani23";
	    byte[] adm=clavedeUsuario.getBytes();
	    
	    ByteBuffer wrapped = ByteBuffer.wrap(adm); // big-endian by default
	    short a = wrapped.getShort(); // 1
	    System.out.println("a  "+a);
	    
	    ByteBuffer wrapped2 = ByteBuffer.wrap(sw); // big-endian by default
	    short w = wrapped2.getShort(); // 1
	    w=300;
	    System.out.println("w  "+w);
	    
	    ByteBuffer wrapped3 = ByteBuffer.wrap(skdc); // big-endian by default
	    short kdc = wrapped3.getShort(); // 1
	    kdc=500;
	    System.out.println("kdc  "+kdc);
	    
	    BigInteger pN= g.pow(a);
	    pN=pN.mod(p);
	    //System.out.println(pN.toString());
	    //int primerN=(int)Math.pow(g.doubleValue(), a);
	 
	    //BigInteger sN= g.pow(kdc).add(g.pow(w));
	    BigInteger sN =g.pow(kdc);
	    BigInteger xs= g.pow(w);
	    xs= xs.mod(p);
	    sN=sN.add(xs);
	    //System.out.println("sn --- "+sN);
	    
	    BigInteger keyf=sN.multiply(pN);
	    //System.out.println("k -- "+keyf);
	    
	    //// tercera parte
	    String ka= keyf.toString();// comparten el kdc y el KDC y el cliente(A o B)
	    String kb= ka;
	    String nameA="A";
	    String nameB="B";
	    Random rand = new Random();
	    int N = 100000 + rand.nextInt(900000);
	    
	    String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
	    char[] passPherase = ka.toCharArray();
	    byte[] salt = "a9v5n38s".getBytes();
	    //mensaje de A-->kdc
	    String secretData = N+":"+nameA+":"+nameB;
        Security.addProvider(new BouncyCastleProvider());
        SealedObject encryptedString = encrypt(secretData,passPherase,salt,algorithm);
        
        //llega al KDC, el KDC tiene guardado el Ka y el Kb
        String decryptedString = decrypt(encryptedString,passPherase,salt,algorithm);
        System.out.println(decryptedString);
        //generate a KAB key
        String Kab= randomString();
        //generate ticket to b
        char[] passPheraseb = kb.toCharArray();
        String mens =Kab+":"+nameA;
        //envia el tickettob
        SealedObject tickettob = encrypt(mens,passPheraseb,salt,algorithm);
        System.out.println(tickettob);
        //envia Kab encri[tada
        String mens2 =Kab;
        SealedObject kabencr = encrypt(mens,passPheraseb,salt,algorithm);
	   //A descript
        //String ticketena = decrypt(tickettob,passPherase,salt,algorithm);
        String kadeencr = decrypt(kabencr,passPherase,salt,algorithm);
        System.out.println("la kab: "+kadeencr);
        // A ---> B 
        /// mandale el ticket a b
        Scanner scanner = new Scanner( new File("publicfileA.txt") );
        String pubA = scanner.useDelimiter("\\A").next();
        scanner.close(); // Put this call in a finally block
        //System.out.println(pubA);
        int M1 = 100000 + rand.nextInt(900000);
		String mestoB=pubA+":"+M1;
		//mandale el objeto encriptado
		char[] passA = kadeencr.split(":")[0].toCharArray();
		SealedObject atob1 = encrypt(mestoB,passA,salt,algorithm);
		 
		///B descript
		//descript el ticket
		 String bdescriptticket = decrypt(kabencr,passPherase,salt,algorithm);
	        System.out.println("ticket que llega a B: "+bdescriptticket + " ----   "+Kab);
	        if(Kab.equals(bdescriptticket.split(":")[0]))
	        {
	        	System.out.println("La kb es la misma, se puede continuar");
	        }
	        else
	        {
	        	System.out.println("No es la misma :c");
	        }
	        char[] passB = Kab.toCharArray();
	        String pubdecript = decrypt(atob1,passB,salt,algorithm);
	        //System.out.println("Pub y M1 en B : "+pubdecript);
	        String pubAinB= pubdecript.split(":")[0];
	        int M1inB= Integer.parseInt(pubdecript.split(":")[1]);
	        //genero M1 con firma de B
	        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
		    Signature.getInstance("RSA");
		    PrivateKey privK= getPrivateKey("privatefileB.txt");
		    signature.initSign(privK, new SecureRandom());
		    String ss= Integer.toString(M1inB);
		    byte[] message = ss.getBytes();
		    //manda el signature
		    signature.update(message);
		    //pubB
		    Scanner scannerb = new Scanner( new File("publicfileB.txt") );
	        String pubB = scannerb.useDelimiter("\\A").next();
	        scannerb.close();
	        //manda la pubb de B a A
	        SealedObject atob2 = encrypt(pubB,passB,salt,algorithm);
	        
	        //llega a A 
	        Signature signdeB= signature;
	        PublicKey pubK= getPublicKeyFromString(pubB);
		    byte[] sigBytes = signdeB.sign();
		    signdeB.initVerify(pubK);
		    signdeB.update(message);
		    System.out.println(signdeB.verify(sigBytes));
		    String pubBinA = decrypt(atob2,passA,salt,algorithm);
		    PublicKey prubKa= getPublicKeyFromString(pubBinA);
	        
	}
	
	static SealedObject encrypt(String data,char[] passPherase,byte[] salt,String algorithm) throws Exception{
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt,20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(passPherase);
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(algorithm);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.ENCRYPT_MODE,secretKey,pbeParamSpec);
	    cipher.doFinal(data.getBytes());
	    //System.out.println(secretKey.);

	    return new SealedObject(data,cipher);
	}
	static String encruptToString(String data,char[] passPherase,byte[] salt,String algorithm)throws Exception
	{
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt,20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(passPherase);
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(algorithm);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.ENCRYPT_MODE,secretKey,pbeParamSpec);
	    cipher.doFinal(data.getBytes());
	    return null;
	}
	
	static String decrypt(SealedObject sealedObject,char[] passPherase,byte[] salt,String algorithm) throws Exception{
	    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt,20);
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(passPherase);
	    SecretKeyFactory secretKeyFactory = 
	        SecretKeyFactory.getInstance(algorithm);
	    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.DECRYPT_MODE,secretKey,pbeParamSpec);
	    return (String)sealedObject.getObject(cipher);
	}
	static String randomString()
	{
		char[] chars = "abcdefghijklmnopqrstuvwxyz".toCharArray();
		StringBuilder sb = new StringBuilder();
		Random random = new Random();
		for (int i = 0; i < 20; i++) {
		    char c = chars[random.nextInt(chars.length)];
		    sb.append(c);
		}
		String output = sb.toString();
		return output;
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
			        System.out.println(fileData.toString());
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
