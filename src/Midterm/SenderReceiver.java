package Midterm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class SenderReceiver {

    private SecretKey symmetricKey;
    private KeyPair AsymmetricKeyPair;

    public SenderReceiver(){

    }

    public void generateSymmetricKey(String algorithm, int keySize) {


        try {
            //Make a key generator that generates AES Keys
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);//AES


            SecureRandom secureRandom = new SecureRandom();
            //Initializes this key generator with the key size and a user-provided source of randomness.
            keyGenerator.init(keySize, secureRandom);

            this.symmetricKey = keyGenerator.generateKey();

        } catch (Exception e) {
            System.out.println("public key generation exception ...");
        }
    }

    public void generateKeyPair(String algorithm, int keySize){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(keySize, random);
            AsymmetricKeyPair = keyGen.generateKeyPair();

        }
        catch(Exception e) {
            System.out.println("public key generation exception ...");
        }
    }

    public PublicKey getPublicKey(){
        return this.AsymmetricKeyPair.getPublic();

    }

    public void encryptMessage(File inFile, File outFile){

        try {
            //File inFile = new File("original.txt");
            //File outFile = new File("encryptedMessage.txt");
            encrypt(symmetricKey, inFile, outFile);
        } catch (NoSuchAlgorithmException e){
            System.out.println("No such Algorithm");
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public SecretKey decryptKey(byte[] encodedKey) {

        byte[] decoded = null;
        SecretKey originalKey = null;
        //System.out.println( "\nStart decryption" );
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, AsymmetricKeyPair.getPrivate());
            decoded = cipher.doFinal(encodedKey);
            originalKey = new SecretKeySpec(decoded, 0, decoded.length, "AES");
            //System.out.println( "Finish decryption: " );
        }
        catch (Exception e) {
            System.out.println("exception   ...");
        }

        return originalKey;

    }

    public void encrypt(SecretKey key, File inputFile, File outputFile)
            throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }
    public byte[] encryptKey(PublicKey asymPublicKey) {

        byte[] encryptedSymKey=null;

        try {

            // get an RSA cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //System.out.println( "\n" + cipher.getProvider().getInfo() );

            // encrypt the plaintext symmetric key using the asymmetric public key
            //System.out.println( "\nStart encryption" );
            cipher.init(Cipher.ENCRYPT_MODE, asymPublicKey);
            encryptedSymKey = cipher.doFinal(symmetricKey.getEncoded());

        }

        catch (Exception e) {

            System.out.println("exception");
        }
        return encryptedSymKey;

    }

    public void decrypt(SecretKey key, File inputFile, File outputFile){
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    private void doCrypto(int cipherMode, SecretKey key, File inputFile, File outputFile){

        String transformation = "AES";
        try {
            //Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            //SecretKeySpec sKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            //Create a cipher that implements the "AES" transformation with the specified mode: cipherMode
            Cipher cipher = Cipher.getInstance(transformation);
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
            System.out.println("Error envcrypting/decrypting file");
        } catch (Exception e){
            System.out.println(e);
        }
    }

}
