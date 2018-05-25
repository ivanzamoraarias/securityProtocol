import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;


public class Ct {

	static boolean conexion=true;
	
	public final static int pValue = 47;
	public final static int gValue = 71;
	
	public static String clientName="A";
	public static String conectTo="B";
	
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		 String host = "localhost";
         int port = 8080;
         InetAddress address = InetAddress.getByName(host);
         
         //Socket socket = new Socket();
         Socket socket = new Socket(address,port); // Create and connect the socket
		//DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
		//DataInputStream dIn = new DataInputStream(socket.getInputStream());
		

		ObjectOutputStream dOut = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream dIn = new ObjectInputStream(socket.getInputStream());
		
		System.out.println("Primero-----------------------------------------------------------");
		int R2=272780;
		firstPartProtocol firstMessage= new firstPartProtocol("publicfileKDC.txt", "A", 272780);
		String first=firstMessage.getMessage();
		dOut.writeUTF(first);
		dOut.flush();
		
		System.out.println("Segundo-----------------------------------------------------------");
		String second= dIn.readUTF();
		System.out.println("Mensaje que llega "+second);
		
		
		System.out.println("Tercero-----------------------------------------------------------");
		String tercero;
		if(R2==Integer.parseInt(second.split(":")[0]))
		{
			firstPartProtocol thirdMessage= new firstPartProtocol();
			String v2=thirdMessage.getDecriptData("privatefileA.txt",second.split(":")[1]);
			//System.out.println("Final llega al cliente  "+v2);
			tercero=v2;
		}
		else
		{
			conexion=false;
			tercero="No se pudo autenticar";
		}
		dOut.writeUTF(tercero);
		dOut.flush();
		
		
		
		System.out.println("2 parte Primero-----------------------------------------------------------");
		BigInteger p = new BigInteger(Integer.toString(pValue));
	    BigInteger g = new BigInteger(Integer.toString(gValue));
		int bitLength = 512; // 512 bits
	    SecureRandom rnd = new SecureRandom();
	    p = BigInteger.probablePrime(bitLength, rnd);
	    g = BigInteger.probablePrime(bitLength, rnd);
	    
	    String clavedeUsuario= "/Gvani23";
	    byte[] adm=clavedeUsuario.getBytes();
	    
	    ByteBuffer wrapped = ByteBuffer.wrap(adm); 
	    short a = wrapped.getShort();
	    BigInteger pN= g.pow(a);
	    pN=pN.mod(p);
	    String sprimero=clientName+":"+pN.toString();
	   
	    dOut.writeUTF(sprimero);
		dOut.flush();
		System.out.println("Se envio ga mod p al kdc");
		
		System.out.println("2 parte Segundo-----------------------------------------------------------");
		//String ssegundo= dIn.readUTF();
		//System.out.println("Lo que llega: "+ssegundo);
		
		BigInteger sN= (BigInteger)dIn.readObject();
		System.out.println("termino bn ");
		
		BigInteger keyf=sN.multiply(pN);
	    System.out.println("k -- "+keyf);
	    
	    
	    System.out.println("Tercera primera------------------------------------------");
	    
	    String ka= keyf.toString();
	    Random rand = new Random();
	    int N = 100000 + rand.nextInt(900000);
	    
	    String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
	    char[] passPherase = ka.toCharArray();
	    byte[] salt = "a9v5n38s".getBytes();
	    
	    String secretData = N+":"+clientName+":"+conectTo;
        Security.addProvider(new BouncyCastleProvider());
        SealedObject encryptedString = encrypt(secretData,passPherase,salt,algorithm);
	    
	    dOut.writeObject(encryptedString);
	    dOut.flush();
	    
	    System.out.println("Se envio");
	    
	    System.out.println("Tercera segunda------------------------------------------");
	    SealedObject tickettob= (SealedObject)dIn.readObject();
	    SealedObject kabencr= (SealedObject)dIn.readObject();
	    
	    String kadeencr = decrypt(kabencr,passPherase,salt,algorithm);
        System.out.println("llego la kab: "+kadeencr);
        
        System.out.println("Tercera tercera------------------------------------------");
        Scanner scanner = new Scanner( new File("publicfileA.txt") );
        String pubA = scanner.useDelimiter("\\A").next();
        scanner.close(); // Put this call in a finally block
        //System.out.println(pubA);
        int M1 = 100000 + rand.nextInt(900000);
		String mestoB=pubA+":"+M1;
		//mandale el objeto encriptado
		char[] passA = kadeencr.split(":")[0].toCharArray();
		SealedObject atob1 = encrypt(mestoB,passA,salt,algorithm);
		dOut.writeObject(atob1);
		dOut.flush();
		
		System.out.println("Tercera cuarta------------------------------------------");
		
		SealedObject atob2 =(SealedObject)dIn.readObject();
		System.out.println("LLegp ");
		
		//Signature signdeB= (Signature)dIn.readObject();
		String pubB=(String)dIn.readObject();
		 byte[] message=(byte[])dIn.readObject();
        PublicKey pubK= getPublicKeyFromString(pubB);
	  //  byte[] sigBytes = signdeB.sign();
	    //signdeB.initVerify(pubK);
	    //signdeB.update(message);
	    //System.out.println(signdeB.verify(sigBytes));
	    String pubBinA = decrypt(atob2,passA,salt,algorithm);
	    PublicKey prubKa= getPublicKeyFromString(pubBinA);
	    System.out.println("Se completo ahora continua la conversaci'on ");
	    
	    BASE64Decoder b64 = new BASE64Decoder();
	    AsymmetricKeyParameter publicKeyB = 
                (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64.decodeBuffer(pubB));
	    AsymmetricBlockCipher e = new RSAEngine();
        e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
        e.init(true, publicKeyB);
        byte[] messageBytes = "holaaaaaaaaaa desde A".getBytes();
        System.out.println("Mensaje en Bytes: "+messageBytes);
        
        byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

        System.out.println(getHexString(hexEncodedCipher));
        String encryptedData = getHexString(hexEncodedCipher);
	    
        dOut.writeUTF(encryptedData);
	    dOut.flush();
	    System.out.println("Finalizada la simulacion");
		dOut.close();
		dIn.close();
		
		
		

	}
	public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
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
