// AES Encryption and Decryption By Alex Tella
// Design and implement a secure and efficient encryption algorithm for protecting sensitive data during transmission and storage.
// Purpose: Test out the Key class
import javax.crypto.SecretKey;


public class Main {
    public static void main(String[] args) throws Exception 
    {
    	String plaintext = "It's time for those 128, 192, and 256 bit keys."; // the plaintext : This is FSM state 1 - the initial state
    	
    	//test out the Key class (standard AES encryption)
        try {
            // test out our encryption and decryption methods
            SecretKey key = Key.generateKey(128); // generate a 128-bit key that
            // encrypt the plaintext
            String encryptedText = Key.encrypt(plaintext, key); // this is  FSM state 2 - transition state
            // decrypt the encrypted text
            String decryptedText = Key.decrypt(encryptedText, key); // this is FSM state 3 - the final state
            System.out.println("Plaintext: " + plaintext);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        	}
        //catch any exceptions
        catch (Exception e) //catch any exceptions
        	{
            e.printStackTrace();
        	}
        	System.out.println();
        
        
        
            //test out the Key class (our own AES encryption)
        	// Input data and key
        	String plaintext_Two = "See you in Rome";
        	System.out.println("Plaintext: " + plaintext_Two);

            // generate our key
            byte[] key = Key.AESKeyGenerator(128);

            // Convert input string to byte array
            byte[] inputData = plaintext_Two.getBytes();

            // encrypt the data using the key
            byte[] encryptedData = Key.encrypt(inputData, key);
            
            // print the encrypted data
            System.out.println("Encrypted Data: " + encryptedData);

            // Decrypt the encrypted data using the same key
            byte[] decryptedData = Key.encrypt(encryptedData, key);

            // Convert decrypted data back to string
            String decryptedString = new String(decryptedData);

            // Display the decrypted data
            System.out.println("Decrypted Data: " + decryptedString);
            
            System.out.println();
            
            
            
            
            
            // Your key should be 16 bytes (128 bits) for AES-128
//            String key3 = "secretkey123456"; 
//            String originalText = "See you in Rome";
//            // encrypt
//            byte[] encryptedText = customKey.encrypt(originalText, key3);
//            System.out.println("Encrypted Text: " + byteArrayToHexString(encryptedText));
//            // decrypt
//            String decryptedText = customKey.decrypt(encryptedText, key3);
//            System.out.println("Decrypted Text: " + decryptedText);
    }
    
    // helper method that converts the bytes to a hexadecimal string
    private static String byteArrayToHexString(byte[] array) 
    {
        StringBuilder buffer = new StringBuilder(); // create a string buffer for our array
    
        for (byte x : array) 
        {
            buffer.append(String.format("%02X", x)); // append the hexadecimal string to the buffer
        }
        return buffer.toString();
    }
    
}