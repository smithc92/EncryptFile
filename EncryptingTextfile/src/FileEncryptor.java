import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Scanner;


public class FileEncryptor {
	private static String KEY_FILENAME="./src/AESkey.bin";
	private static int ITERATIONS=1000;
	
	//driver
	public static void main (String[] args)throws Exception{
		Scanner scan = new Scanner(System.in);
		//you need to get password from user as well as the name for inputfile and outputfile.
		System.out.println("Please enter password...");
		String password = scan.nextLine();
		char[] pw = password.toCharArray();
		System.out.println("Please enter inputfile name...");
		String in = scan.nextLine();
		System.out.println("Please enter outputfile...");
		String out = scan.nextLine();
		
		createKey(pw);
		//loadKey(pw);
		encrypt(pw,in,out);
		System.out.println("Please enter input file name...");
		//String in2 = scan.nextLine();
		System.out.println("Please enter decrypted file name...");
		String out2 = scan.nextLine();
		decrypt(pw, out, out2);
	}



private static void createKey(char[] password) throws Exception{
	System.out.println("Generating a AES key...");
	
	//create AES key
	String method = "AES";
    KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
    keyGen.init(256);
    Key aesKey = keyGen.generateKey();
    
	
	System.out.println("Done generating the key.");
	
	//Now we want to encrypt the key with a password. We will create an 8-byte salt and create
	//a password based encryption cipher with the password
	Random r = new Random();
	byte[] salt = new byte[8];
	r.nextBytes(salt);
	
	System.out.println("Salt:(createKey)" + CryptoUtils.toHex(salt));
	PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS);
	
    //Key key = kf.generateSecret(keySpec);
    Cipher cEnc = Cipher.getInstance(method);
 	cEnc.init(Cipher.ENCRYPT_MODE, aesKey);
 	
 	byte[] EncAesKey = cEnc.doFinal(aesKey.getEncoded());
 	System.out.println("Key Bytes:(createKey)" + CryptoUtils.toHex(EncAesKey));
	
	//we can use the cipher to encrypt the encoded form of the key.
	
	//Encrypt the key.
	
	//in order to decrypt the key, we need to have a salt. We will write the salt that we generated
	//to the first 8 bytes of the file, and then we will write the encrypted key and close the file

 	FileOutputStream fos = new FileOutputStream(KEY_FILENAME);
 	fos.write(salt);
 	fos.write(EncAesKey);
 	fos.close();
	
}

//Before we can do any file encryption and decryption, we need to have access to the key.
//The method called loadkey() will load a key, with password specified as argument.
//This essentially is a reverse of creatKey() method.
//We read in the salt and the encrypted key bytes, then decrypt the key with 
//password based encryption cipher.
//load a key from the filesystem.


private static Key loadKey(char[] password) throws Exception{
	//Load bytes from encrypted key file.
	byte data[] = readFromFile(KEY_FILENAME);

	//get the salt, which is first 8 bytes.
	int i = 0;
	byte[] saltBytes = new byte[8];
	System.out.println("Here: " + CryptoUtils.toString(data));

	while(i<8)
	{
		saltBytes[i] = data[i];
		++i;
	}
	
	System.out.println("Salt:(loadKey)" + CryptoUtils.toHex(saltBytes));
	//get encrypted key bytes
	int j = 0;
	
	byte[] encKeyBytes = new byte[data.length-saltBytes.length];
	while(i<data.length)
	{
		encKeyBytes[j] = data[i];
		++i;
		++j;
	}
	System.out.println("EncryptedKeyBytes: (loadKey)" + CryptoUtils.toHex(encKeyBytes));
	
	//Create PBE cipher
	PBEKeySpec pbeSpec = new PBEKeySpec(password, saltBytes, ITERATIONS);
    String method = "PBEWithSHAAnd3KeyTripleDES";
    SecretKeyFactory keyFact = SecretKeyFactory.getInstance(method);
    Cipher cDec = Cipher.getInstance(method, "BC");
    Key sKey = keyFact.generateSecret(pbeSpec);
    cDec.init(Cipher.DECRYPT_MODE, sKey);
	//Decrypt key bytes
    byte[] keyBytes = sKey.getEncoded();
	//Create key from key bytes
    Key key = new SecretKeySpec(keyBytes, 0, keyBytes.length, method);
	return key;
}


//read bytes from given files
private static byte[] readFromFile(String textFile) throws IOException
{
	FileInputStream fis = new FileInputStream(textFile);
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	int i = 0;
	while((i=fis.read()) != -1)
	{
		baos.write(i);
	}
	fis.close();
	byte[] message = baos.toByteArray();
	baos.close();
	return message;
}




//Encrypt file using AES key. Load key from file system, given a password.
private static void encrypt(char[] password, String fileInput, String fileOutput) throws Exception{
	//loading the key
	Key key = loadKey(password);
	//
	String method = "AES/CBC/PKCS5Padding";
	//Create a cipher using that key to initialize it
	Cipher cipher = Cipher.getInstance(method, "BC");
	cipher.init(Cipher.ENCRYPT_MODE, key);
	//Now we need an Initialization vector for cipher in CBC mode. We use 16 bytes, because the
	//block size of Rijnadael is 128 bits.
	
	
	SecureRandom randomIV = new SecureRandom();	
	byte[] IVBytes = new byte[16];
	randomIV.nextBytes(IVBytes);
	IvParameterSpec IvParam = new IvParameterSpec(IVBytes);
	cipher.init(Cipher.ENCRYPT_MODE, key, IvParam);
	FileInputStream fis = new FileInputStream(fileInput);
	FileOutputStream fos = new FileOutputStream(fileOutput); //write encrypted file out
	
	//Now we want to wrap a CipherOutputStream around the FileOutputStream using the cipher
	//we just created.
	fos.write(IVBytes);
	//wrap cipher w/ output stream. You can write and encrypt at some time.
	CipherOutputStream cos = new CipherOutputStream(fos,cipher); //<-Get instance (init)
	System.out.println("Encrypting the file...");
	int theByte = 0;
	
	
	//We simply read the bytes from the input stream and write them to the cipher stream.  
	//This will encrypt the entire file.  Close input and output.
	//-1 means you reach end of file
	while((theByte = fis.read()) != -1){
			cos.write(theByte);
	}
	fis.close();
	cos.close();
	
	//We will open the files for reading and writing. We will write the IV bytes to the output
	//file unencrypted, as we will need to use it later to decrypt the file.
	//Then we will creat IVParameterSpec
	//object that we will use to create a cipher
	System.out.println("Done Encrypting the File.");
		
}



//Decrypting the file is the opposite.  Read the iv, initialize cipher, create CipherInputStream
//use it to decrypt file.
//Decrypt a file using Rijndael. Load the key from filesystem, given a password.

private static void decrypt(char[] password, String fileInput, String fileOutput) throws Exception{
	
	//Loading the key
	Key key = loadKey(password);
	//Create a cipher using key to initialize it
	
	//Read IV from the file. It is the first 16 bytes and initalize the cipher.
	
	//Create CipherInputStream and use it to decrypt the file.
	
	//fis
	FileInputStream fis = new FileInputStream(fileInput);
	
	//fos
	FileOutputStream fos = new FileOutputStream(fileOutput);
	
	byte[] ivBytes = new byte[16];
	fis.read(ivBytes);
	IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
	cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	CipherInputStream cis = new CipherInputStream(fis,cipher);
	int theByte = 0;
	while((theByte = cis.read()) != -1)
	{
		fos.write(theByte);
	}
	cis.close();
	fos.close();
	
	

}
}
