import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Key 
{
	//generate a symmetric key (a key that it used both for encrypting and decrypting)
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException 
	{
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); //AES is a symmetric key algorithm
	    keyGenerator.init(n); //n is the size of the key in bits
	    SecretKey originalKey = keyGenerator.generateKey(); //generate a key
	    return originalKey; //return the key
	}
	
	//encrypt and decrypt methods
	public static String encrypt(String plaintext, SecretKey key) throws Exception 
	{
		Cipher cipher = Cipher.getInstance("AES"); //grabs the AES cipher from KeyGenerator
        cipher.init(Cipher.ENCRYPT_MODE, key); //initialize the cipher to encrypt
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); 	//do the encryption
        return Base64.getEncoder().encodeToString(encryptedBytes); //return the encrypted text
    }
	
	//decrypt method
    public static String decrypt(String encryptedText, SecretKey key) throws Exception 
    {
    	Cipher cipher = Cipher.getInstance("AES"); //grabs the AES cipher from KeyGenerator
        cipher.init(Cipher.DECRYPT_MODE, key); //initialize the cipher to decrypt
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText); //decode the encrypted text
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes); //do the decryption
        return new String(decryptedBytes); //return the decrypted text
    }
    
    
    
    
    
    // making our own key
    public static byte[] AESKeyGenerator(int n)
    {
    	// create a "round constant" array using hexadecimal values
		byte[] rcon = new byte[] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, (byte)0x1b, (byte)0x36 }; // this is the round constant array // round_key array is set with 10 elemens one for each round
    	
    	// do XOR mathmatics with the round constant and the key
		byte[] round_key = new byte[16];
		round_key[0] = (byte)0x2b; // this is the first round key
		
		for(int i = 1; i < 10; i++)
		{
			round_key[i] = (byte)(round_key[i-1] ^ rcon[i-1]); // first we do XOR mathmatics with the round constant-1 and the key and then we do XOR mathmatics with the previous round key and the round constant-1
			// shift the rowss of the round key
			 if (i % 4 == 0) // modulo 4 because we are shifting the rows by 4 bits
			 {
				 //shift the rows by more bitwise operations
				 byte temp = round_key[i - 3]; // we need to shift the rows by 4 bits so we need to store the first byte in a temporary variable
		         round_key[i - 3] = round_key[i - 2]; // we shift the first byte by 4 bits
		         round_key[i - 2] = round_key[i - 1]; // we shift the second byte by 4 bits
		         round_key[i - 1] = temp; // we shift the third byte by 4 bits

			  }
		}
		
		return byteToHex(round_key); // return the round key
    }
    
    // convert a byte array to a hexadecimal string
    public static byte[] byteToHex(byte[] arr) 
    {
        // create a byte array to store the result
        byte[] array_list = new byte[arr.length * 2];

        // loop through the byte array
        for (int i = 0, j = 0; i < arr.length; i++)
        {
            // append the byte to the byte array
            int value = (arr[i] & 0xff) + 0x100; // we need to add 0x100 to the value incase the value is less then 8 bytes
            array_list[j++] = (byte) Integer.parseInt(Integer.toString(value, 16).substring(1), 16); // we need to re-arrange the hexadecimal string //
        }

        // return the byte array
        return array_list;
    }

    // convert a hexadecimal string to a byte array
   public static byte[] hexToByte(String hex) 
    {
        int len = hex.length();  // get the length of the string
        byte[] data = new byte[len / 2]; // divide the length by 2 since we are converting 2 characters at a time
        // loop through the string
        for (int i = 0; i < len; i += 2)
        {
        	// convert the string into a byte array by converting the string into a character array and then converting the character array into a byte array
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) +Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    } 
   
   public static byte[] encrypt(byte[] data, byte[] key) 
   {
       int blockSize = 16; // AES block size is 16 bytes
       int numBlocks = (data.length + blockSize - 1) / blockSize; // divide the length of the data by the block size
       byte[] encrypted = new byte[numBlocks * blockSize]; // create a byte array to store the encrypted data

       for (int i = 0; i < numBlocks; i++) 
       {
           byte[] block = new byte[blockSize];
           System.arraycopy(data, i * blockSize, block, 0, Math.min(blockSize, data.length - i * blockSize));

           // XOR the block with the key
           for (int j = 0; j < blockSize; j++) 
           {
               block[j] ^= key[j]; //use the key to XOR the block
           }
        
           // copy the block into the encrypted byte array by using the block size as the length of the array to copy over to the encrypted byte array and then use the block size as the offset for the encrypted byte array 
           System.arraycopy(block, 0, encrypted, i * blockSize, blockSize);
       }

       return encrypted;
   }
 
}
