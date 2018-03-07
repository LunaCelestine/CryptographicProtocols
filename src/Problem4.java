
import java.io.File;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Problem4 {

    public static void main(String[] args){

/*        The idea of Bob and Alice being two separate individuals communicating with each other
        is simulated by the instantiation of two separate SenderReceiver objects. Aside from some basic utility and
        processing function calls, the idea is that each SenderReceiver encrypts, decrypts, and verifies data independently
        of the other object.*/


        SenderReceiver bob = new SenderReceiver();
        SenderReceiver alice = new SenderReceiver();

        File inFile = new File("originalMessage.txt");
        File encryptedFile = new File("encryptedMessage.txt");
        File outFile = new File("decryptedMessage.txt");

        alice.generateKeyPair("RSA", 1024);
        bob.generateSymmetricKey("AES", 128);

        //Bob encrypts message with his symmetric key
        bob.encrypt(bob.getSymmetricKey(), inFile, encryptedFile, "AES");

        //Alice sends Bob her public key, Bob encrypts the symmetric key with her public key
        byte[] encryptedKey = bob.encryptKey(bob.getSymmetricKey().getEncoded(), alice.getPublicKey());

        //"Transmit" Bob's encrypted message, decrypt the encrypted key, use decrypted key to decrypt message
        byte[] decryptedKeyBytes = alice.decryptKey(encryptedKey, alice.getPrivateKey());
        SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
        alice.decrypt(decryptedKey, encryptedFile, outFile, "AES");

    }

}
