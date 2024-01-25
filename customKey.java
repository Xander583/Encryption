// Alex Tella

import java.util.Arrays;

//not functional yet but is far more aligned toward the AES methodoloy
public class customKey 
{
	// encrypts Data using AES method
    public static byte[] encrypt(String text, String key) 
    {
        byte[] input = text.getBytes(); // convert the text to a byte array
        byte[] keyBytes = key.getBytes(); // convert the key to a byte array

        // make round keys for key expansion phase
        byte[][] roundKeys = keyExpansion(keyBytes); // this is where we will be doing the matrix manipulation that is the core of AES encryption

        // make the first round key since all others depend on it and work off of the previous round key
        addRoundKey(input, roundKeys[0]);

        // shuffle all the data around
        for (int round = 1; round < 10; round++) 
        {
            subBytes(input); // use rijndael's s-box to substitute the bytes
            shiftRows(input); // shift the rows
            mixColumns(input); // mix the columns
            addRoundKey(input, roundKeys[round]); // progress to the next round key by adding the previous round key to the current round key
        }

        // last round of matrix manipulation
        subBytes(input);
        shiftRows(input);
        addRoundKey(input, roundKeys[10]);

        return input;
    }

    public static String decrypt(byte[] cipherText, String key)
    {
        byte[] keyBytes = key.getBytes();

        // key expansion phase
        byte[][] roundKeys = keyExpansion(keyBytes);

        // Initial round
        addRoundKey(cipherText, roundKeys[10]);
        invShiftRows(cipherText);
        invSubBytes(cipherText);

        // do matrix manipulation for the main rounds
        for (int round = 9; round > 0; round--) 
        {
            addRoundKey(cipherText, roundKeys[round]);
            invMixColumns(cipherText);
            invShiftRows(cipherText);
            invSubBytes(cipherText);
        }

        // last round of of key expansion
        addRoundKey(cipherText, roundKeys[0]);

        return new String(cipherText);
    }

    private static byte[][] keyExpansion(byte[] key) 
    {
    	int keyWord = key.length /4; // keyword is the length of the key divided by 4 used for 
    	int keySize = 4*(10+1); // new keySize has 10 rounds plus 1 (but remember we need to multiple by 4 because of the bytes)
    	byte[][] expandedKey = new byte[keySize][4]; // creates a new 2D array for the expanded key (this is where we will be doing the matrix mathmatics eventually) this is the core of AES encryption
    	
    	// copy the key into the expanded key
		for (int i = 0; i < keyWord; i++) 
		{
			expandedKey[i][0] = key[i * 4];
			expandedKey[i][1] = key[i * 4 + 1];
			expandedKey[i][2] = key[i * 4 + 2];
			expandedKey[i][3] = key[i * 4 + 3];
		}
		
		// loop through the expanded key
		for (int i = keyWord; i < keySize; i++)
		{
			byte[] temp = Arrays.copyOf(expandedKey[i - 1], 4); // copy the previous key into a temporary variable
			
			// if the key is a multiple of the round constant (r_con) we need to do some XOR mathmatics
			if(i%4==0)
			{
				// shift the rows
				byte temp1 = temp[0]; // we need to shift the rows by 4 bits so we need to store the first byte in a temporary variable
				temp[0] = temp[1]; // we shift the first byte by 4 bits
				temp[1] = temp[2]; // we shift the second byte by 4 bits
				temp[2] = temp[3]; // we shift the third byte by 4 bits
				temp[3] = temp1; // we shift the fourth byte by 4 bits
			
			}
			
			// do XOR mathmatics with the round constant and the key
			for (int j = 0; j < 4; j++) 
			{
				// take our key and and do XOR mathmatics with the round constant
				expandedKey[i][j] = (byte) (expandedKey[i - keyWord][j] ^ temp[j]); // this is where we are shifting out matrix (4x4 blocks)
			}
		}
		return expandedKey;
    }
    
    // AES SubBytes (substitution box) method to obscure the data
    private static void subBytes(byte[] data) 
    {
    	// loop through the data array
    	for (int i = 0; i < data.length; i++) 
    	{
            int row = (data[i] >>> 4) & 0x0F; // shift the bits to the right by 4  then perform bitwise operation with 0x0F (hexadecimal representation of binary) which will get the first 4 bits which will be the row
            int col = data[i] & 0x0F; // same as above but we do not need to shift the bits to the right because we want the last 4 bits which will be the column

            // obscure the data
            data[i] = sbox[row][col];  // use rijndael's s-box to substitute the bytes
        }
    }
    
    // shift the rows of the data
    private static void shiftRows(byte[] data)
    {
    	//shift all rows except the first one
        for (int i = 1; i < 4; i++)
        {
            int shiftAmount = i * 4;  // calculate the amount we are going to be shifting the rows by

            // the row shift
            for (int j = 0; j < 4; j++) 
            {
                int index = i * 4 + j; // calculate the index of the row
                int destinationIndex = (i * 4 + j + shiftAmount) % 16; // calculate the destination index of the row

                byte temp = data[index]; // store the data in a temporary variable
                data[index] = data[destinationIndex]; // shift the data
                data[destinationIndex] = temp; // store the data in the destination index
            }
        }
    }
    
    // AES MixColumns method to obscure the data
    private static void mixColumns(byte[] data)
    {
    	// loop through the data array
    	for (int i = 0; i < 4; i++) 
    	{
    		// store the data in a temporary variable
            int d0 = data[i];
            int d1 = data[i + 4]; // store the data 4 bits to the right
            int d2 = data[i + 8]; // store the data 8 bits to the right
            int d3 = data[i + 12]; // store the data 12 bits to the right
            
            // do matrix mathmatics
            data[i] = (byte) (multiplyBy2(d0) ^ multiplyBy3(d1) ^ d2 ^ d3); //uses other columns to get the new value for the first column
            data[i + 4] = (byte) (d0 ^ multiplyBy2(d1) ^ multiplyBy3(d2) ^ d3); //continues the process for each
            data[i + 8] = (byte) (d0 ^ d1 ^ multiplyBy2(d2) ^ multiplyBy3(d3));
            data[i + 12] = (byte) (multiplyBy3(d0) ^ d1 ^ d2 ^ multiplyBy2(d3));
        }
    }
    
    //helper function for mixColumns
    private static int multiplyBy2(int value) 
    {
    	// shift bits left by 1 and then performs bitwise operation on it, we check if the MSB (most significant bit (left most bit)) is a 1 or 0
        return (value << 1) ^ ((value & 0x80) != 0 ? 0x1b : 0); //use galois field mathmatics to get the new value
    }
    
    //helper function for mixColumns
    private static int multiplyBy3(int value) 
    {
    	
    	// perform bitwise operation on multiply2 with the data value itself
        return multiplyBy2(value) ^ value;
    }
    
    
    //adds a new round key to the data
    private static void addRoundKey(byte[] data, byte[] roundKey) 
    {
    	// loop through the data array 16 times since we are using 128 bit keys which is a 4x4 matrix
    	for (int i = 0; i < 16; i++) 
    	{
            data[i] ^= roundKey[i]; // perform bitwise operation on round constant
        }
    }
    
    //reverse sub bytes (reverse s-box)
    private static void invSubBytes(byte[] data) 
    {
    	// loop through the data array
    	for (int i = 0; i < data.length; i++) 
    	{
            int row = (data[i] >>> 4) & 0x0F; // shift bits back to the right by 4  then perform bitwise operation with 0x0F (hexadecimal representation of binary) which will get the first 4 bits which will be the row
            int col = data[i] & 0x0F; // same as above but we do not need to shift the bits to the right because we want the last 4 bits which will be the column
            data[i] = inversesbox[row][col]; // use inverse s-box to substitute the bytes
        }
    }
    
    //reverse shift rows
    private static void invShiftRows(byte[] data) 
    {   
      //shift all rows except the first one
        for (int i = 1; i < 4; i++)
        {
            int shiftAmount = i * 4;  // calculate the amount we are going to be shifting the rows by

            // the row shift
            for (int j = 0; j < 4; j++) 
            {
                int index = i * 4 + j; // calculate the index of the row
                int destinationIndex = (i * 4 + j + shiftAmount) % 16; // calculate the destination index of the row

                byte temp = data[index]; // store the data in a temporary variable
                data[index] = data[destinationIndex]; // shift the data
                data[destinationIndex] = temp; // store the data in the destination index
            }
        }
    }
    
    //reverse mix columns
    private static void invMixColumns(byte[] data) 
    {
    	// loop through the data array
    	for (int i = 0; i < 4; i++) 
    	{
    		// store the data in a temporary variable
            int d0 = data[i];
            int d1 = data[i + 4]; // store the data 4 bits to the right
            int d2 = data[i + 8]; // store the data 8 bits to the right
            int d3 = data[i + 12]; // store the data 12 bits to the right
            
            // do matrix mathmatics
            data[i] = (byte) (multiplyBy2(d0) ^ multiplyBy3(d1) ^ d2 ^ d3); //uses other columns to get the new value for the first column
            data[i + 4] = (byte) (d0 ^ multiplyBy2(d1) ^ multiplyBy3(d2) ^ d3); //continues the process for each
            data[i + 8] = (byte) (d0 ^ d1 ^ multiplyBy2(d2) ^ multiplyBy3(d3));
            data[i + 12] = (byte) (multiplyBy3(d0) ^ d1 ^ d2 ^ multiplyBy2(d3));
        }
    }
    
    // AES S-Box (substitution box) (this is the base of which AES works off of developed in the Rijndael cipher)
    // this matrix is mapped to its multiplicative inverse based off of a "finite field" using "Galois Field" mathmatics. This is essentially using rational numbers to do modulo mathmatics in a way that is not possible with most normal integers
    public static final byte[][] sbox = {
    		{0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76}, 
    		{(byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0}, 
    		{(byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15}, 
    		{0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75}, 
    		{0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84}, 
    		{0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf}, 
    		{(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8}, 
    		{0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2}, 
    		{(byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
    		{0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb},
    		{(byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79}, 
    		{(byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08}, 
    		{(byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a}, 
    		{0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e}, 
    		{(byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf}, 
    		{(byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16}
    					              }; //https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
    
    // AES Inverse S-Box (substitution box)
    public static final byte[][] inversesbox = {
    		{0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38, (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
    		{0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
    		{0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e},
    		{0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24, (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1, 0x25},
    		{0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c, (byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92},
    		{0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
    		{(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7, (byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06},
    		{(byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b},
    		{0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73},
    		{(byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7, (byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75, (byte) 0xdf, 0x6e},
    		{0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e, (byte) 0xaa, 0x18, (byte) 0xbe, 0x1b},
    		{(byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4},
    		{0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27, (byte) 0x80, (byte) 0xec, 0x5f},
    		{0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
    		{(byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61},
    		{0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    									};
    									
}
