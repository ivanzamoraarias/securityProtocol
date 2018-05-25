
public class Test {
	
	public static void main(String[] args) {
		//A-->KDC: A, {R2}KDC
		int R2=272780;
		firstPartProtocol firstMessage= new firstPartProtocol("publicfileKDC.txt", "A", 272780);
		String first=firstMessage.getMessage();
		System.out.println("Mensaje del cliente "+first);
		
		//KDC-->A: R2, {R1}A
		String clientName= first.split(":")[0];
		String rFromClient= first.split(":")[1];
		firstPartProtocol secondMessage= new firstPartProtocol();
		String v=secondMessage.getDecriptData("privatefileKDC.txt", rFromClient);
		System.out.println("des serv "+v);
		secondMessage.publicKeyFile="publicfileA.txt";
		secondMessage.saludo=v;
		secondMessage.R=997197;
		String second= secondMessage.getMessage();
		System.out.println("Mensaje del KDC "+second);
		
		//A-->KDC:R1
		if(R2==Integer.parseInt(second.split(":")[0]))
		{
			firstPartProtocol thirdMessage= new firstPartProtocol();
			String v2=thirdMessage.getDecriptData("privatefileA.txt",second.split(":")[1]);
			System.out.println("Final llega al cliente  "+v2);
		}
	}

}
