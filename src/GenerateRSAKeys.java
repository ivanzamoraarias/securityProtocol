

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import sun.misc.BASE64Encoder;

/*
 * 
 * BIBLIOGRAFIA:
 * [1] JAVA generate RSA Public and Private Key Pairs using bouncy castle Crypto APIs
 * 			http://www.mysamplecode.com/2011/08/java-generate-rsa-key-pair-using-bouncy.html
 */
public class GenerateRSAKeys{

    public static void main(String[] args)
    {

        String publicKeyFilename = null;
        String privateKeyFilename = null;

        GenerateRSAKeys generateRSAKeys = new GenerateRSAKeys();

        publicKeyFilename = "publicfileB.txt";
        privateKeyFilename = "privatefileB.txt";
        generateRSAKeys.generate(publicKeyFilename, privateKeyFilename);
        

    }

    private void generate (String publicKeyFilename, String privateFilename){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
         
            
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            BASE64Encoder encode64 = new BASE64Encoder();

            SecureRandom random = createFixedRandom();
            //generator.initialize(1024, random);
            //generator.initialize(4096, random);
            generator.initialize(2048);
            
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            System.out.println("publicKey : " + encode64.encode(pubKey.getEncoded()));
            System.out.println("privateKey : " + encode64.encode(privKey.getEncoded()));

            BufferedWriter out = new BufferedWriter(new FileWriter(publicKeyFilename));
            out.write(encode64.encode(pubKey.getEncoded()));
            out.close();

            out = new BufferedWriter(new FileWriter(privateFilename));
            out.write(encode64.encode(privKey.getEncoded()));
            out.close();


        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    public static SecureRandom createFixedRandom()
    {
        return new NumeroRandom();
    }

    private static class NumeroRandom extends SecureRandom {

        MessageDigest sha;
        byte[] state;

        NumeroRandom() {
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1");//produce un valor de 20 bytes
                this.state = sha.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
            	e.printStackTrace();
                
            }
        }

        public void nextBytes(byte[] bytes){

            int    off = 0;

            sha.update(state);

            while (off < bytes.length)
            {                
                state = sha.digest();

                if (bytes.length - off > state.length)
                {
                    System.arraycopy(state, 0, bytes, off, state.length);
                }
                else
                {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }

                off += state.length;

                sha.update(state);
            }
        }
    }

}