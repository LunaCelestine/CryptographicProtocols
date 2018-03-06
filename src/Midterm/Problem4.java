package Midterm;

import java.io.File;

public class Problem4 {

    public static void main(String[] args){

        SenderReceiver bob = new SenderReceiver();
        SenderReceiver alice = new SenderReceiver();

        File inFile = new File("original.txt");
        File encryptedFile = new File("encryptedMessage.txt");
        File outFile = new File("decryptedMessage.txt");

        alice.generateKeyPair("RSA", 1024);
        bob.generateSymmetricKey("AES", 128);
        bob.encryptMessage(inFile, encryptedFile);
        byte[] encryptedKey = bob.encryptKey(alice.getPublicKey());//"Transmit" Alice's public key to Bob, Bob encrypts the Key
        alice.decrypt(alice.decryptKey(encryptedKey), encryptedFile, outFile);//"Transmit" Bob's encrypted message, decrypt the encrypted key, use decrypted key to decrypt message

    }

}
