import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
 
public class Cliente
{
 
    private static Socket socket;
 
    public static void main(String args[])
    {
        try
        {
            String host = "localhost";
            int port = 25000;
            InetAddress address = InetAddress.getByName(host);
            socket = new Socket(address, port);
 
            
            System.out.println("Primero-----------------------------------------------------------");
            //Send the message to the server
            OutputStream os = socket.getOutputStream();
            OutputStreamWriter osw = new OutputStreamWriter(os);
            BufferedWriter bw = new BufferedWriter(osw);
 
            int R2=272780;
    		firstPartProtocol firstMessage= new firstPartProtocol("publicfileKDC.txt", "A", 272780);
    		String first=firstMessage.getMessage();
    		System.out.println("Mensaje del cliente "+first);
 
            String sendMessage = first + "\n";
            bw.write(sendMessage);
            bw.flush();
            System.out.println("Message sent to the server : "+sendMessage);
 
            
            System.out.println("Segundo-----------------------------------------------------------");
            //Get the return message from the server
            InputStream is = socket.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String message = br.readLine();
            System.out.println("Message received from the server : " +message);
            String second= message;
            
            
            ///tercera parte
            System.out.println("Tercero-----------------------------------------------------------");
            if(R2==Integer.parseInt(second.split(":")[0]))
    		{
    			firstPartProtocol thirdMessage= new firstPartProtocol();
    			String v2=thirdMessage.getDecriptData("privatefileA.txt",second.split(":")[1]);
    			System.out.println("Final llega al cliente  "+v2);
    			
    			 //OutputStream os3 = socket.getOutputStream();
    	        // OutputStreamWriter osw3 = new OutputStreamWriter(os3);
    	        // BufferedWriter bw3 = new BufferedWriter(osw3);
    	            
    	            //String sendMessage = first + "\n";
    	         bw.write(v2);
    	         bw.flush();
    	         System.out.println("Message sent to the server : "+v2);
    		}
            else 
            {
            	//OutputStream os3 = socket.getOutputStream();
   	         //OutputStreamWriter osw3 = new OutputStreamWriter(os3);
   	         //BufferedWriter bw3 = new BufferedWriter(osw3);
   	            
   	            //String sendMessage = first + "\n";
   	         bw.write("No se pudo autenticar");
   	         bw.flush();
   	         System.out.println("Message sent to the server : No se pudo autenticar");
            }
           
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }
        finally
        {
            //Closing the socket
            try
            {
                socket.close();
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }
    }
}