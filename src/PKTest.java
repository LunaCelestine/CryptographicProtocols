import java.io.*;
import java.security.*;
// make sure to include this line below
import java.nio.file.*;

public class PKTest {

    public static void main(String[] args) {

        byte [] fileContent=null;
        PublicKey pub=null;
        byte[] realSig=null;

        try{

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            keyGen.initialize(1024, random);

            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            pub = pair.getPublic();
            Signature rsa = Signature.getInstance("SHA256withRSA");

            rsa.initSign(priv);

            String inputFile="Company.java";
            FileInputStream fis = new FileInputStream(inputFile);
            fileContent = new byte[(int)inputFile.length()];
            // the following two lines are new
            // they are needed to read the data bytes from the file
            // and store them in the byte array.
            Path path = Paths.get("Company.java");
            fileContent=Files.readAllBytes(path);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                rsa.update(buffer, 0, len);
            };
            bufin.close();
            realSig = rsa.sign();
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }

        System.out.println(verifySignature(pub, fileContent, realSig));

    }

    public static boolean verifySignature(PublicKey pubKey, byte[] message, byte[] signature) {
        Signature sig = null;
        try {
            sig = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sig.initVerify(pubKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            sig.update(message);
            return sig.verify(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;

    }

}
