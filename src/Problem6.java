import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;

public class Problem6 {

    public static void main(String[] args) {

        SenderReceiver bob = new SenderReceiver();
        SenderReceiver alice = new SenderReceiver();

        File inFile = new File("originalMessage.txt");
        File encryptedFile = new File("encryptedMessage.txt");
        File outFile = new File("decryptedMessage.txt");

        //Alice generates a 1024 bit RSA keypair
        alice.generateKeyPair("RSA", 1024);

        //Bob generates a 128 bit AES symmetric key
        bob.generateSymmetricKey("AES", 128);

        //Alice sends Bob her public key, Bob uses Alice's public key to encrypt his symmertic key
        byte[] encryptedKeyA = bob.encryptKey(bob.getSymmetricKey().getEncoded(), alice.getPublicKey());

        //Bob generates a 2048 bit RSA keypair
        bob.generateKeyPair("RSA", 2048);

        //Bob uses his 2048 bit RSA private key to encrypt the encrypted key A
        byte[] encryptedKeyB = bob.encryptKey(encryptedKeyA, bob.getPrivateKey());

        //Bob uses the symmetric key to encrypt the message
        bob.encrypt(bob.getSymmetricKey(), inFile, encryptedFile, "AES");

        //Bob generates a hash of encryptedKeyB
        String hashB = bob.generateHash(encryptedKeyB, "SHA-256");
        //Bob generates a hash of message, encryptedFile
        String hashM = bob.generateHash(fileToBytes(encryptedFile), "SHA-256");

        //Bob sends S, M, and his public key to Alice

        //Alice compares key hashes, if both hashes are match, then she begins decryption
        if(alice.compareHashes(alice.generateHash(encryptedKeyB, "SHA-256"), hashB)){
            if(alice.compareHashes(alice.generateHash(fileToBytes(encryptedFile), "SHA-256"), hashM)){

                //Alice uses bob's public key to decrypt the key, then uses her own private key to decrypt that key
                byte[] originalKeyBytes = alice.decryptKey(alice.decryptKey(encryptedKeyB, bob.getPublicKey()), alice.getPrivateKey());

                //This simply generates a SecretKey object from the byte array
                SecretKey originalKey = new SecretKeySpec(originalKeyBytes, 0, originalKeyBytes.length, "AES");

                //Alice decrypts the file using the decrypted key
                alice.decrypt(originalKey, encryptedFile, outFile, "AES");
            }
        }

    }

    public static byte[] fileToBytes(File f) {
        //A helper function to clean up main
        byte[] fileContents = new byte[(int) f.length()];
        return fileContents;
    }
}

