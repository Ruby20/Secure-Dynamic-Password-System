import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;


@SuppressWarnings("unused")
public class Server {

	/**
	 * @param args
	 * @throws Exception 
	 */

	static int SR;
	static long X;
	static ObjectOutputStream toClient;
	static ObjectInputStream fromClient;
	static FileOutputStream out;
	static FileInputStream in ;

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		ServerSocket socket = new ServerSocket(9295);



		//creating Storage file
		//File file;
		//file = new File("server.txt");
		out = (new FileOutputStream("server.txt",true));
		in = (new FileInputStream("server.txt"));




		//accepting connection from client
		Socket connectionSocket = socket.accept();
		OutputStream ostream_client = connectionSocket.getOutputStream();
		InputStream istream_client = new DataInputStream(connectionSocket.getInputStream());

		toClient = new ObjectOutputStream(ostream_client);  
		fromClient= new ObjectInputStream(istream_client);  




		System.out.println("Server started.");



		X=123456789L;
		//X= generateX();

		while (true){
			//receiving SR value from the client
			try{
				SR = (int)fromClient.readObject(); 
			}
			catch (EOFException e){
				break;
			}
			if(SR>5)
				break;
			SRhandler();
		}

		//closing connection
		out.close();
		socket.close();

	}


	@SuppressWarnings("deprecation")
	public static int SRhandler() throws Exception{

		Hash_and_Encrypt eh = new Hash_and_Encrypt();
		SecureRandom rand = new SecureRandom ();
		boolean login_verified = false;
		String ID =null;
		byte[] h_PW;
		int g = 0,p=0;
		long [] B;
		long[] B_square;
		long[] D_square;
		if (SR==0){
			//Registration Phase
			in = (new FileInputStream("server.txt"));

			System.out.println("Server starts registration");
			//receiving ID and h(PW)
			ID = (String)fromClient.readObject();  
			h_PW= (byte [])fromClient.readObject();

			//choose g, p
			g=Math.abs((byte)Math.abs(rand.nextInt()));
			
			//making sure that p is prime
			boolean prime= false;
			while(prime == false){
				//generate p
				p=Math.abs((byte)Math.abs(rand.nextInt()));
				prime=eh.prime_test(p);
			}
			
			
			
			//compute B and B_square

			byte [] X_byte=ByteBuffer.allocate(8).putLong(X).array();
			byte [] ID_byte= ID.getBytes();
			byte [] XconcID = new byte [X_byte.length+ID_byte.length];

			System.arraycopy(X_byte,0,XconcID,0         ,X_byte.length);
			System.arraycopy(ID_byte,0,XconcID,X_byte.length,ID_byte.length);

			//computing h(X||ID)
			byte [] h_XconcID = eh.SHA1(XconcID);

			//computing h(x||ID)+h(PW)
			int []  h_xconcID_plus_h_PW = new int [h_XconcID.length];
			for (int i =0;i<h_XconcID.length;i++){
				h_xconcID_plus_h_PW[i]= (h_XconcID[i])+(h_PW[i]);}

			//computing B=g^h(x||ID)+h(PW) mod p
			B= new long [h_xconcID_plus_h_PW.length];

			for(int i =0 ; i<h_xconcID_plus_h_PW.length;i++){
				B[i]= eh.modPow(g, h_xconcID_plus_h_PW[i], p);
			}


			//sending g,p,B to client
			toClient.writeObject(g);  
			toClient.writeObject(p);
			toClient.writeObject(B);


			//computing B_square
			B_square= new long[B.length];
			for(int i =0 ; i<B.length;i++){
				B_square[i]= eh.modPow(B[i],2,p);
			}

			 D_square= new long[B.length];
			for(int i =0 ; i<B.length;i++){
				D_square[i]= eh.modPow(B_square[i],h_PW[i],p);
			}

			//storing ID,g,p,B_square
			out.write(ID.getBytes());
			//out.write("\n");
			byte[] g_Bytes = ByteBuffer.allocate(4).putInt(g).array();
			out.write(g_Bytes);
			//out.writeObject("\n");
			byte[] p_Bytes = ByteBuffer.allocate(4).putInt(p).array();
			out.write(p_Bytes);
			//out.writeObject("\n");
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream stream = new DataOutputStream(byteStream);

			for(int i =0; i<D_square.length;i++)
				stream.writeLong(D_square[i]);


			byte[] D_square_bytes =    byteStream.toByteArray();
			out.write(D_square_bytes);
			out.flush();

			System.out.println("Server sent B");


			in.close();
			return 1;


		}
		else if (SR==1){
			//Login Phase

			in = (new FileInputStream("server.txt"));

			//receive the user ID
			ID = (String)fromClient.readObject();

			//get ID record
			byte [] line= new byte[ID.getBytes().length];
			while ((  in.read(line)) !=-1) {
				// check if line == ID
				if (Arrays.equals(line, ID.getBytes())) {
					System.out.println("ID record found");
					break;
				} 
			}
			byte [] g_Bytes=new byte[4];
			in.read(g_Bytes);
			final ByteBuffer byteBuffer = ByteBuffer.wrap(g_Bytes);
			g =byteBuffer.getInt(0);

			byte [] p_Bytes=new byte[4];
			in.read(p_Bytes);
			final ByteBuffer byteBuffer2 = ByteBuffer.wrap(p_Bytes);
			p =byteBuffer2.getInt(0);

			D_square= new long [20];
			byte [] D_square_Bytes=new byte[20*8];
			in.read(D_square_Bytes);

			ByteArrayInputStream bais = new ByteArrayInputStream(D_square_Bytes);
			DataInputStream dis = new DataInputStream(bais);

			for(int i=0; i<D_square.length; i++)
				D_square[i] = dis.readLong();




			//choose random R
			byte R=2;
			
			//making sure that R is even and not equal to p-1
			boolean even= false;
			while(even == false || R== p-1){
				//generate p
				R= (byte) Math.abs((byte)Math.abs(rand.nextInt()));
				if (R%2==0)
					even=true;
			}
			//byte R=5;
			//compute B_dbl_dash

			byte [] X_byte=ByteBuffer.allocate(8).putLong(X).array();
			byte [] ID_byte= ID.getBytes();
			byte [] XconcID = new byte [X_byte.length+ID_byte.length];

			System.arraycopy(X_byte,0,XconcID,0         ,X_byte.length);
			System.arraycopy(ID_byte,0,XconcID,X_byte.length,ID_byte.length);

			//computing h(X||ID)
			byte [] h_XconcID = eh.SHA1(XconcID);

			//computing g^h(X||ID)mod p
			long [] g_h_X = new long [h_XconcID.length];

			for (int i = 0 ; i<g_h_X.length;i++){
				g_h_X[i]=eh.modPow(g, h_XconcID[i], p);
			}

			//compute B_dbl_dash= (g^h(X||ID) mod p)^R
			long[] B_dbl_dash= new long [g_h_X.length];

			for(int i =0 ; i<g_h_X.length;i++){
				//System.out.println(p);
				B_dbl_dash[i]= eh.modPow(g_h_X[i], R, p);
			}

			//computing h_B_dbl_dash
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream stream = new DataOutputStream(byteStream);

			for(int i =0; i<B_dbl_dash.length;i++)
				stream.writeLong(B_dbl_dash[i]);


			byte[] B_dbl_dash_bytes =    byteStream.toByteArray();

			byte [] h_B_dbl_dash = eh.SHA1(B_dbl_dash_bytes);

			//sending h(B_dbl_dash) and R to the client
			toClient.writeObject(h_B_dbl_dash);  
			toClient.writeObject(R);

			//receiving C and timestamp T from the server
			boolean verified_flag= (boolean)fromClient.readObject();

			if(verified_flag==false){
				System.out.println("Verification failed at client side");
				return 0;
			}
			
			Timestamp T = (Timestamp)fromClient.readObject();
			long [] C = (long [])fromClient.readObject();

			//getting current timestamp T_dash
			Timestamp T_dash = new Timestamp(System.currentTimeMillis()); 	

			//comparing T and T_dash
			long diff =compareTwoTimeStamps (T_dash,T) ;
			long delta_T = 5;
			if(diff>delta_T){
				System.out.println("Timestamp check failed");
				return 0;
			}

			//compute C_dash
			//compute R+T
			long T_l = T.getTime();
			long R_T = R*T_l;


			//compute C_dash= (D^2)^(R+T)) mod p
			long[] C_dash= new long [D_square.length];

			for(int i =0 ; i<D_square.length;i++){
				C_dash[i]= eh.modPow( D_square[i],R_T, p);
			}

			//compute C_sqr
			long [] C_sqr = new long [C.length];
			for(int i =0 ; i<C_sqr.length;i++){
				C_sqr[i]= eh.modPow( C[i],2, p);
			}

			//comparing C and C_dash
			if (Arrays.equals(C_sqr, C_dash))
			{
				//login success
				System.out.println("Login Authenticated");
				login_verified=true;

			}
			else{
				//login failure
				System.out.println("Login failed");
				return 0;
			}




			if(SR==2 && login_verified){
				//Data exchange

			}
			else if (SR==3&&login_verified){
				//Password change
			}
		}
		in.close();
		return 1;
	}

	public static long generateX(){

		SecureRandom rand = new SecureRandom ();
		long X;
		return X=rand.nextLong();
	}

	public static long compareTwoTimeStamps(java.sql.Timestamp currentTime, java.sql.Timestamp oldTime)
	{
		long milliseconds1 = oldTime.getTime();
		long milliseconds2 = currentTime.getTime();

		long diff = milliseconds2 - milliseconds1;
		long diffSeconds = diff / 1000;
		long diffMinutes = diff / (60 * 1000);
		long diffHours = diff / (60 * 60 * 1000);
		long diffDays = diff / (24 * 60 * 60 * 1000);

		return diffMinutes;
	}
	
	public static long compareTwoTimeStamps(long currentTime_milli, long oldTime_milli)
	{
		long milliseconds1 = currentTime_milli;
		long milliseconds2 = oldTime_milli;

		long diff = milliseconds2 - milliseconds1;
		long diffSeconds = diff / 1000;
		long diffMinutes = diff / (60 * 1000);
		long diffHours = diff / (60 * 60 * 1000);
		long diffDays = diff / (24 * 60 * 60 * 1000);

		return diffMinutes;
	}
}
