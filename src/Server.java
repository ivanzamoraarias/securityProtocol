import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
 
public class Server
{
 
    private static Socket socket;
 
    public static void main(String[] args)
    {
        try
        {
 
            int port = 25000;
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server Started and listening to the port 25000");
 
            //Server is running always. This is done using this while(true) loop
            while(true)
            {
                //Reading the message from the client
            	System.out.println("Primero-----------------------------------------------------------");
                socket = serverSocket.accept();
                InputStream is = socket.getInputStream();
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String first = br.readLine();
                System.out.println("Message received from client is "+first);
 
                //Multiplying the number by 2 and forming the return message
                //String returnMessage= number;
              
 
                
                //////////second one
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
                //String returnMessage2= second;
                //Sending the response back to the client.
                OutputStream os = socket.getOutputStream();
                OutputStreamWriter osw = new OutputStreamWriter(os);
                BufferedWriter bw = new BufferedWriter(osw);
                bw.write(second);
                System.out.println("Message sent to the client is "+second);
                bw.flush();
                
                System.out.println("Tercero-----------------------------------------------------------");
                //socket = serverSocket.accept();
                //InputStream is3 = socket.getInputStream();
                //InputStreamReader isr3 = new InputStreamReader(is3);
                //BufferedReader br3 = new BufferedReader(isr3);
                String therd = br.readLine();
                System.out.println("Message received from client is "+therd);

               
                
              
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                socket.close();
            }
            catch(Exception e){}
        }
    }
}