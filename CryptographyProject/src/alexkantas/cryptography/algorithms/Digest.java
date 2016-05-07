package alexkantas.cryptography.algorithms;

import alexkantas.cryptography.functions.CryptFunction;
import java.security.*;

/**
 *
 * @author Alexandros Kantas
 */
public class Digest {

    private MessageDigest message;

    public Digest() {
        setMessageAlgorithm("SHA512");
    }

    /**
     * Calculates digest
     *
     * @param plaintext plaintext string
     * @return digest
     */
    public byte[] Calc(String plaintext) {
        return message.digest(plaintext.getBytes());
    }

    /**
     * Calculates digest
     *
     * @param plaintext plaintext bytes
     * @return digest
     */
    public byte[] Calc(byte[] plaintext) {
        return message.digest(plaintext);
    }

    /**
     * Sets algorithm to calculate the message
     *
     * @param digest_algorithm
     */
    public final void setMessageAlgorithm(String digest_algorithm) {

        try {
            message = MessageDigest.getInstance(digest_algorithm);
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public static void main(String[] args) {

        CryptFunction alg = new CryptFunction();
        Digest digest = new Digest();
        byte[] randomDataDigest = digest.Calc("Alex");

        System.out.println("\nMessage: PLAINTEXT "
                + "\n\nSHA512 (HEX DUMP): "
                + alg.toHexString(randomDataDigest)
                + "\nSize (bits): "
                + randomDataDigest.length * 8);
    }

}
