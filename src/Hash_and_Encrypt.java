import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class Hash_and_Encrypt {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

Hash_and_Encrypt o = new Hash_and_Encrypt();
long b =2L;
long e=6L;

System.out.println(o.Pow(b, e));
	}

	public  byte[] SHA1(byte[] mesaage)throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-1");

		md.update(mesaage, 0, mesaage.length);

		byte[] mdbytes = md.digest();
		return mdbytes;


	}

	public  byte[] hash(byte[] mesaage)throws Exception {
		byte[] salt = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 65536, 128);
		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = f.generateSecret(spec).getEncoded();
		return hash;
	}

	public  long modPow(long base, long exponent, long modulus){
		long result = 1;
		if (exponent<0){
			base =  modInverse(base,modulus);
			exponent= Math.abs(exponent);
		}
		while (exponent > 0){
			if (exponent % 2 == 1)
				result = (result * base) % modulus;
			exponent = exponent >> 1;
			base = (base * base) % modulus;
		}
		return result;
	}
	
	public  long modPow1(long base, long exponent, long modulus){
		if (exponent<0){
			base =  modInverse(base,modulus);
			exponent= Math.abs(exponent);
		}
		
		long result = (long) pow(base, exponent,modulus);

		return result;
	}
	
	public  long Pow(long base, long exponent){
		long result = 1;
		while (exponent > 0){
			if (exponent % 2 == 1)
				result = (result * base) ;
			exponent = exponent >> 1;
			base = (base * base) ;
		}
		return result;
	}
	
	/* This function calculates (a^b)%MOD */
	static long pow(long a, long b, long MOD) {
	long x = 1, y = a;
	    while(b > 0) {
	        if(b%2 == 1) {
	            x=(x*y);
	            if(x>MOD) x%=MOD;
	        }
	        y = (y*y);
	        if(y>MOD) y%=MOD;
	        b /= 2;
	    }
	    return x;
	}
	 
	static long modInverse(long a, long m) {
	    return pow(a,m-2,m);
	}

public boolean prime_test(long num) {
	    
	    for (long i = 2; i*i <= num; ++i)
	        if (num % i == 0)
	            return false;
	    return true;
	}

	

}
