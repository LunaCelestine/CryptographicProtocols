import java.security.*;
import javax.crypto.*;
//
// Public Key cryptography using the RSA algorithm.

// you can also interchange publicKey vs publicKey
// as it reads, the message certifies the receiver
// But the data for encryption cannot exceed 117 bytes for 1024 bit modulus
// 245 bytes for 2048 bit modulus
//501 bytes for 4096 bit modulus

public class KeyEncryption {

    public static void main(String[] args) throws Exception {

        KeyPair asymmetricKeyPair = null;

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(1024,random);
            asymmetricKeyPair = keyGen.generateKeyPair();
            System.out.println( "Finish generating RSA key" );
        }
        catch(Exception e) {
            System.out.println("public key generation exception ...");
        }

        byte[] symmetricKey = genKey();
        byte[] encryptedSymmetricKey = encodeKey(symmetricKey, asymmetricKeyPair);
        byte[] decKey = decodeKey (encryptedSymmetricKey, asymmetricKeyPair);


    }

    public static byte[] genKey ( ) {
        //This method generates an AES symmetric key
        SecretKey secretSymmetricKey = null;

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

            SecureRandom secureRandom = new SecureRandom();
            int keyBitSize = 128;
            keyGenerator.init(keyBitSize, secureRandom);

            secretSymmetricKey = keyGenerator.generateKey();
        }
        catch (Exception e ) {
            System.out.println("error");
        }


        return secretSymmetricKey.getEncoded();

    }

    public static byte[] encodeKey (byte[] symKey, KeyPair asymKeyPair) {

        byte[] encryptedSymKey=null;

        try {

            //
            // get an RSA cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            System.out.println( "\n" + cipher.getProvider().getInfo() );
            //
            // encrypt the plaintext symmetric key using the asymmetric public key
            System.out.println( "\nStart encryption" );
            cipher.init(Cipher.ENCRYPT_MODE, asymKeyPair.getPublic());
            encryptedSymKey = cipher.doFinal(symKey);

        }

        catch (Exception e) {

            System.out.println("exception");
        }
        return encryptedSymKey;

    }

    public static byte[] decodeKey (byte[] encodedKey, KeyPair kp) {

        byte[] decoded =null;
        System.out.println( "\nStart decryption" );
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            decoded = cipher.doFinal(encodedKey);
            System.out.println( "Finish decryption: " );
        }
        catch (Exception e) {
            System.out.println("exception   ...");
        }
        return decoded;

    }
}
