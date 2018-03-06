package Midterm;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptoUtilities {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {

        try {
            //Make a key generator that generates AES Keys
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");


            SecureRandom secureRandom = new SecureRandom();
            //Specify the size of the key
            int keyBitSize = 128;
            //Initializes this key generator with the key size and a user-provided source of randomness.
            keyGenerator.init(keyBitSize, secureRandom);

            SecretKey secretKey = keyGenerator.generateKey();

            File inFile = new File("original.txt");
            File outFile = new File("encryptedMessage.txt");
            File outFile2 = new File("decrypted.txt");//TODO: sender doesn't need this

            //Encrypt the inFile, generate outfile, decrypt outfile, generate outFile2
            encrypt(secretKey,inFile,outFile);
            decrypt(secretKey,outFile,outFile2);//TODO: sender doesn't need this

        } catch (InvalidKeyException e) {
            System.out.println("error");
        }

    }

    public static void encrypt(SecretKey key, File inputFile, File outputFile)
            throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    public static void decrypt(SecretKey key, File inputFile, File outputFile)
            throws Exception {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    private static void doCrypto(int cipherMode, SecretKey key, File inputFile,
                                 File outputFile) throws Exception {
        try {
            //Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            //SecretKeySpec sKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            //Create a cipher that implements the "AES" transformation with the specified mode: cipherMode
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, key);

            //Read the file into inputStream and place in the buffer, inputBytes
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            //Encrypt/Decrypt the byte array using AES key according to the mode set by cipherMode
            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new Exception("Error encrypting/decrypting file", ex);
        }
    }
}
