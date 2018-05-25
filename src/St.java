import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import sun.misc.BASE64Decoder;


public class St {
	
	public final static int pValue = 47;
	public final static int gValue = 71;

	public static void main(String[] args) throws Exception {
		int port = 8080;
		ServerSocket serverSocket = new ServerSocket(port);
		//ServerSocket socket = new ServerSocket(port); // Set up receive socket
		//Socket socket= new Socket();
		Socket socket=serverSocket.accept();
		
		//DataInputStream dIn = new DataInputStream(socket.getInputStream());
		//DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
		
		ObjectInputStream dIn = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream dOut = new ObjectOutputStream(socket.getOutputStream());

		System.out.println("Primero-----------------------------------------------------------");
		String first= dIn.readUTF();
		System.out.println("Ha llegado: "+first);
		
		System.out.println("Segundo-----------------------------------------------------------");
		String clientName= first.split(":")[0];
		String rFromClient= first.split(":")[1];
		firstPartProtocol secondMessage= new firstPartProtocol();
		String v=secondMessage.getDecriptData("privatefileKDC.txt", rFromClient);
		System.out.println("des serv "+v);
		secondMessage.publicKeyFile="publicfileA.txt";
		secondMessage.saludo=v;
		secondMessage.R=997197;
		String second= secondMessage.getMessage();
		dOut.writeUTF(second);
		dOut.flush();
		
		System.out.println("Tercero-----------------------------------------------------------");
		String tercero= dIn.readUTF();
		System.out.println("Ha llegado: "+tercero);
				

		
		
		System.out.println("2 parte Primero-----------------------------------------------------------");
		BigInteger p = new BigInteger(Integer.toString(pValue));
	    BigInteger g = new BigInteger(Integer.toString(gValue));
		int bitLength = 512; // 512 bits
	    SecureRandom rnd = new SecureRandom();
	    p = BigInteger.probablePrime(bitLength, rnd);
	    g = BigInteger.probablePrime(bitLength, rnd);
		
	    String sprimero= dIn.readUTF();
	    System.out.println("LLego: "+sprimero);
	    BigInteger pN= new BigInteger(sprimero.split(":")[1]);
	    System.out.println("pN --- "+pN);
		
	    System.out.println("2 parte Segundo-----------------------------------------------------------");
	    short w=300;
	    short kdc=500;
	    BigInteger sN =g.pow(kdc);
	    BigInteger xs= g.pow(w);
	    xs= xs.mod(p);
	    sN=sN.add(xs);
	    
	    //dOut.writeUTF(sN.toString());;
	    //dOut.flush();
	   // oos.writeObject(sN);
	    
	    //System.out.println("Se envio " +sN.toString());
	    dOut.writeObject(sN);
	    //System.out.println("Se envio " +sN.toString());
	    
	    BigInteger keyf=sN.multiply(pN);
	    System.out.println("k -- "+keyf);
	    
	    System.out.println("Tercera primera------------------------------------------");
	    String ka= keyf.toString();
	    String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
	    char[] passPherase = ka.toCharArray();
	    byte[] salt = "a9v5n38s".getBytes();
	    
	    SealedObject encryptedString= (SealedObject)dIn.readObject();
	    String decryptedString = decrypt(encryptedString,passPherase,salt,algorithm);
        System.out.println("Si llego "+decryptedString);
        //generate a KAB key
        String Kab= randomString();
        
        System.out.println("Tercera segunda------------------------------------------");
      //generate ticket to b
        String kb= ka;///// solo como auxiliar 
        char[] passPheraseb = kb.toCharArray();
        String mens =Kab+":"+"A";
        //envia el tickettob
        SealedObject tickettob = encrypt(mens,passPheraseb,salt,algorithm);
        dOut.writeObject(tickettob);
        dOut.flush();
        //envia Kab encri[tada
        String mens2 =Kab;
        SealedObject kabencr = encrypt(mens,passPheraseb,salt,algorithm);
        dOut.writeObject(kabencr);
        dOut.flush();
	    System.out.println("LLego //");
	    
	    
	    /////////////////////A continuacion El servidor hace de cliente B , por conveniencia de demostracion del protocolo no se ha creado otro cliente
	    System.out.println("Tercera Tercera, ahora como B------------------------------------------");
	    
	    SealedObject atob1=(SealedObject)dIn.readObject();
	    
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
        
        
        System.out.println("Tercera Cuarta, ahora como B------------------------------------------");

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
	    signature.update(message);
	    //pubB
	    Scanner scannerb = new Scanner( new File("publicfileB.txt") );
        String pubB = scannerb.useDelimiter("\\A").next();
        scannerb.close();
        SealedObject atob2 = encrypt(pubB,passB,salt,algorithm);
        dOut.writeObject(atob2);
        dOut.flush();
        //dOut.writeObject(signature);
        //dOut.flush();
        dOut.writeObject(pubB);
        dOut.flush();
        dOut.writeObject(message);
        dOut.flush();
        
        
        System.out.println("Se completo ahora continua la conversaci'on ");
        String getMfromA=dIn.readUTF();
        System.out.println("Esto llego "+getMfromA);
        
        String key = readFileAsString("privatefileB.txt");
        BASE64Decoder b64 = new BASE64Decoder();
        AsymmetricKeyParameter privateKey = 
            (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decodeBuffer(key));
        AsymmetricBlockCipher e = new RSAEngine();
        e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
        e.init(false, privateKey);

        byte[] messageBytes = hexStringToByteArray(getMfromA);
        byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

        System.out.println(new String(hexEncodedCipher));
        String outputData = new String(hexEncodedCipher);
        
        System.out.println("Finalizada la simulacion");
		dIn.close();
		dOut.close();
		
		
		
		
	}
	public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
	
	public class clientAThread implements Runnable
	{

		@Override
		public void run() {
			// TODO Auto-generated method stub
			try {
				this.mainMethod();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		
		public void mainMethod() throws IOException
		{
			
		}
		
	}
	public class clientBThread implements Runnable
	{

		@Override
		public void run() {
			// TODO Auto-generated method stub
			try {
				this.mainMethod();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		
		public void mainMethod() throws IOException
		{
			
		}
		
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
