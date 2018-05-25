import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import sun.misc.BASE64Decoder;
 
public class RSADecryption {
 
    public static void main(String[] args)
    {
 
    	
        String privateKeyFilename = "privatefileK.txt";
        String encryptedData = "6abc1102f34e47ae8222307333f53f97d386805f453103c03a5d65baef8a73fc44bbe5b8aa0bcb0eaba56c97d6f5146b16f4e6374bca5b381af125518dc27cc7342d34f8976bbd5f07cd140432513785ab3308a48a66eed032a6249654972b854d0b75bf81f74a2096a9ff1c7fadac5b88c54220d4508847ad1c55ee30e7abcfa63f7d2062a3af2e6d4af9a9d1e00e6885ad163587a2d5101a634b99060d9533a4a257235d676ce54ec1471415e1d731cffcf1f8e1a03646e92ffaaf91a21382e944d1c6bcb22b47faab0e096e049eb64dfe2831a1818d5e72117414266cbe05da464e6ea7e7cd6507dd8f8e03e67d88718d43077619e954dc6250807ab50ea2";
        
        RSADecryption rsaDecryption = new RSADecryption();
 
     
        rsaDecryption.decrypt(privateKeyFilename, encryptedData);
        
        /*if (args.length < 2)
        {
            System.err.println("Usage: java "+ rsaDecryption.getClass().getName()+
            " Private_Key_Filename Encrypted_String_Data");
            System.exit(1);
        }
 
        privateKeyFilename = args[0].trim();
        encryptedData = args[1].trim();
        rsaDecryption.decrypt(privateKeyFilename, encryptedData);
 */
    }
 
    private void decrypt (String privateKeyFilename, String encryptedFilename, String outputFilename){
 
        try {
 
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
            String key = readFileAsString(privateKeyFilename);
            BASE64Decoder b64 = new BASE64Decoder();
            AsymmetricKeyParameter privateKey = 
                (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decodeBuffer(key));
            
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);
            
            String inputdata = readFileAsString(encryptedFilename);
            byte[] messageBytes = hexStringToByteArray(inputdata);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
 
            System.out.println(new String(hexEncodedCipher));
            BufferedWriter out = new BufferedWriter(new FileWriter(outputFilename));
            out.write(new String(hexEncodedCipher));
            out.close();
 
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
    
    private String decrypt (String privateKeyFilename, String encryptedData) {
 
        String outputData = null;
        try {
 
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
 
            String key = readFileAsString(privateKeyFilename);
            BASE64Decoder b64 = new BASE64Decoder();
            AsymmetricKeyParameter privateKey = 
                (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decodeBuffer(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);
 
            byte[] messageBytes = hexStringToByteArray(encryptedData);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
 
            System.out.println(new String(hexEncodedCipher));
            outputData = new String(hexEncodedCipher);
 
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return outputData;
    }
 
    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
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
 
}