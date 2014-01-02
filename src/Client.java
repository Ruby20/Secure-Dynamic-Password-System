
import java.net.*;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.Arrays;
import java.io.*;

public class Client {

	static FileOutputStream out;
	static FileInputStream in ;
	static  int choice;
	static int g = 0,p = 0;
	static long [] B = null;
	static ObjectOutputStream toServer;
	static ObjectInputStream fromServer;
	static BufferedReader Stdin;
	
	@SuppressWarnings("resource")
	public static void main(String[] args)throws Exception {
		 
		  //client socket
		     Socket client = new  Socket("localhost",9295);
		 
		     
		     
		   //Take input from User
		  
		   InputStream istream_server = client.getInputStream();
		   OutputStream istream_client = client.getOutputStream();
		   
		   toServer = new ObjectOutputStream(istream_client);  
		   fromServer= new ObjectInputStream(istream_server);  

		   
		   
		   
		  int dont_exit_flag=1;
		   while (true){
				//receiving SR value from the client
				try{
					 System.out.println("Enter your choice : Enter 0 to Register and 1 to Login");
					   Stdin = new BufferedReader(new InputStreamReader(System.in));
					  choice =  Integer.parseInt(Stdin.readLine());
				}
				catch (EOFException e){
					break;
				}
				if(choice>5)
					break;
				dont_exit_flag = SRhandler();
				//if(dont_exit_flag==0)
					//client.close();
			}

		  
		   
		  
		  client.close(); 
		

	}

	public static int SRhandler() throws Exception{
		   Hash_and_Encrypt td = new Hash_and_Encrypt();

		
		 if(choice == 0){
			 //Registration Phase
			    System.out.println("User wants to register");
			    
			   //send the service request to the server
			    toServer.writeObject(choice);
			    System.out.println("Enter your ID ");
			    String ID = Stdin.readLine();
			    System.out.println("Enter your password");
			    String password = Stdin.readLine();
			     
			    if (password == null || password.length() == 0)throw new IllegalArgumentException("Empty passwords are not supported.");
		            
			  
			    byte[] hash = td.SHA1(password.getBytes());
			   
			    System.out.println("client sending ID, h(PW)");
			    // send the id and hash(password) to the server
			    toServer.writeObject(ID);
			    toServer.writeObject(hash);
			    // receive g,p and B values from the server
			      g = (int)fromServer.readObject();
			      p = (int)fromServer.readObject();
			      B = (long[])fromServer.readObject();
	            	//System.out.println(p);

			    System.out.println("client received B");
			    out = (new FileOutputStream(ID+".txt"));
			    //storing g,p,B
			    byte[] g_Bytes = ByteBuffer.allocate(4).putInt(g).array();
				out.write(g_Bytes);
				//out.writeObject("\n");
				byte[] p_Bytes = ByteBuffer.allocate(4).putInt(p).array();
				out.write(p_Bytes);
         	//System.out.println(p);

				//out.writeObject("\n");
			    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				DataOutputStream stream = new DataOutputStream(byteStream);

				for(int i =0; i<B.length;i++)
					stream.writeLong(B[i]);


				byte[] B_bytes =    byteStream.toByteArray();
				out.write(B_bytes);
				out.flush();
				out.close();
           }
		   
		   
		   
		   
		   
		   
		   
		   
		      if(choice == 1){
		    	  //Login Phase
		    	  System.out.println("user wants to login");
				  
				   //client sends the service request to the server
				   
				   System.out.println("Login:Enter your ID to login");
				   String ID1 = Stdin.readLine();
				   System.out.println("Login:Enter your password to login");
				   String passwd = Stdin.readLine();
				   
				   try {
						in = (new FileInputStream(ID1+".txt"));}
					   catch(FileNotFoundException e){
						   System.out.println("You entered wrong ID");
						   return 0;
					   }
				   
				   toServer.writeObject(choice);
				   toServer.writeObject(ID1);  //send Id and password to the server
				   //toServer.writeObject(passwd);  
				   
				   
				   //reading g,p,B
				   byte [] g_Bytes=new byte[4];
					in.read(g_Bytes);
					final ByteBuffer byteBuffer = ByteBuffer.wrap(g_Bytes);
					g =byteBuffer.getInt(0);

					byte [] p_Bytes=new byte[4];
					in.read(p_Bytes);
					final ByteBuffer byteBuffer2 = ByteBuffer.wrap(p_Bytes);
					p =byteBuffer2.getInt(0);
	            	//System.out.println(p);

				   B= new long [20];
					byte [] B_Bytes=new byte[20*8];
					in.read(B_Bytes);

					ByteArrayInputStream bais = new ByteArrayInputStream(B_Bytes);
					DataInputStream dis = new DataInputStream(bais);

					for(int i=0; i<B.length; i++)
						B[i] = dis.readLong();
				   
				   byte[] hashP = td.SHA1(passwd.getBytes()); //compute a hash on the password
				   
				   
				   // receive h(B"),R from the server
				   byte[] hash_dbl_dash = (byte[])fromServer.readObject();
				   byte R = (byte)fromServer.readObject();
				  
				   			        
				   //Verification
				   
				   
	                //compute B' = ((Bg^(-h(PW))^R mod p)				   
				     
				   //compute g^(-h(pw)) mod p				     
				     long g_pow [] = new long [hashP.length];
				     for(int i=0;i < hashP.length; i++){
				    	g_pow[i] =td.modPow(g, -1*hashP[i], p); ;
				    	 
				     }
				     
				     long B_g [] =new long [hash_dbl_dash.length];
				     
				     for(int i=0;i < hash_dbl_dash.length; i++){
				    	  B_g[i] =(B[i]*g_pow[i])%p;
				    	 
				    }
				     
				     long B_prime [] =new long [hash_dbl_dash.length];

				     for(int i=0;i < hash_dbl_dash.length; i++){
				    	 B_prime[i] =td.modPow(B_g[i], R,p);

				     }
				     
				               
		            //verify hash(B') = hash(B")
		            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				    DataOutputStream stream = new DataOutputStream(byteStream);
				    
				    for(int i =0; i<B_prime.length;i++)
				    	stream.writeLong(B_prime[i]);
				      
				    
				    byte[] B_Calc_prime_bytes =    byteStream.toByteArray();
		             byte[] hash_B_prime = td.SHA1(B_Calc_prime_bytes);
		             
		             boolean verified_flag= true;
		             if(Arrays.equals(hash_dbl_dash, hash_B_prime)){
		            	 System.out.println("Hashes of B_prime and B_Dbl_prime match ");
		            	 verified_flag=true;
		             }
		             else{
		            	 System.out.println("verification failed");
		            	 System.out.println("You either entered wrong password or the server is not verified");
		            	 verified_flag=false;
					        toServer.writeObject(verified_flag);

		            	 return 0;
		             }
		            
		             
		             toServer.writeObject(verified_flag);

		             
		             //calculate D = B^h(pw) mod p
		             long[] D = new long [B.length];
		             for (int i =0; i<D.length;i++){
				        	D[i] = td.modPow(B[i], hashP[i], p);
				        }
		             
		             
		             
		             
		             //compute c = D ^(T + R) mod p
		            Timestamp T= new Timestamp(System.currentTimeMillis());
		            toServer.writeObject(T); // send T to the server
			        long Time = T.getTime();
			        long RT =  Time * R;
			        
			        long[] c = new long [D.length];
			        for (int i =0; i<D.length;i++){
			        	c[i] = td.modPow(D[i], RT, p);
			        }
			        
			        toServer.writeObject(c);
			        in.close();
			}
		
		return 1;
	}

}
