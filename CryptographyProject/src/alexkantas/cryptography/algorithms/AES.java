package alexkantas.cryptography.algorithms;

import alexkantas.cryptography.functions.CryptFunction;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Alexandros Kantas
 */
public class AES {

    private String plaintext;
    private SecretKey AES_key;
    private BouncyCastleProvider bcp = new BouncyCastleProvider();
    private CryptFunction alg = new CryptFunction();
    private Cipher AES_Cipher;

    public AES() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(bcp); // using the Bouncycastle provider
        AES_Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC"); // make a Cipher object for AES with ECB mode and PKCS5 Padding, 
    }

    //<editor-fold desc="Attribute modifier methods">
    /**
     * Generates a radom 256-bit AES key
     *
     */
    public void genarateKey() throws NoSuchAlgorithmException {
        KeyGenerator AES_keygen = KeyGenerator.getInstance("AES"); //make a KeyGenerator object for AES 
        AES_keygen.init(256, new SecureRandom()); //init the generator to produce 256-bit keys and use a random seed
        SecretKey AES_key = AES_keygen.generateKey();
        this.AES_key = AES_key;
    }

    /**
     * Sets a new 256-bit AES key
     *
     * @param keyString Key in HEX String
     */
    public void setkey(String keyString) {
        byte[] keyBytes = Hex.decode(keyString.getBytes());
        SecretKey AES_key = new SecretKeySpec(keyBytes, "AES");
        this.AES_key = AES_key;
    }

    /**
     * Sets a new 256-bit AES key
     *
     * @param AES_key SecretKey AES_key
     */
    public void setkey(SecretKey AES_key) {
        this.AES_key = AES_key;
    }

    /**
     * @return Current AES SecretKey
     */
    public SecretKey getkey() {
        return AES_key;
    }
    // </editor-fold>

    //<editor-fold desc="Encrypt Decrypt Methods">
    /**
     * Encrypt a message
     *
     * @param plaintext Sting of text to encrypt
     * @return Hex String of ciphertext
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String encrypt(String plaintext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES_Cipher.init(Cipher.ENCRYPT_MODE, AES_key);

        //<editor-fold desc="Print info" defaultstate="collapsed">
//        System.out.print("Encrypting a " + plaintext.getBytes().length * 8
//                + "-bit Plaintext using "
//                + AES_key.getEncoded().length * 8 + "-bit "
//                + AES_Cipher.getAlgorithm()
//                + " (" + AES_Cipher.getBlockSize() * 8
//                + "-bit Blocks) ... ");
        // </editor-fold>
        byte ciphertext[] = AES_Cipher.doFinal(plaintext.getBytes());

        //<editor-fold desc="Print info" defaultstate="collapsed">
//        System.out.println("OK");
//        System.out.println("Ciphertext:" + alg.toHexString(ciphertext));
        //</editor-fold>
        return alg.toHexString(ciphertext);
    }

    /**
     * Encrypt a message
     *
     * @param plaintext Byte to encrypt
     * @return Byte ciphertext
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(byte[] plaintext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES_Cipher.init(Cipher.ENCRYPT_MODE, AES_key);

        byte ciphertext[] = AES_Cipher.doFinal(plaintext);

        return ciphertext;
    }

    /**
     * Decrypt a message
     *
     * @param ciphertext Sting of HEX ciphertext to decrypt
     * @return Hex String text
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt(String ciphertext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES_Cipher.init(Cipher.DECRYPT_MODE, AES_key);

        byte dplaintext[] = AES_Cipher.doFinal(alg.fromHexString(ciphertext));

        return alg.toHexString(dplaintext);
    }

    /**
     * Decrypt a message
     *
     * @param ciphertext byte ciphertext to decrypt
     * @return original text in byte
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt(byte[] ciphertext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES_Cipher.init(Cipher.DECRYPT_MODE, AES_key);

        byte dplaintext[] = AES_Cipher.doFinal(ciphertext);

        return dplaintext;
    }

    // </editor-fold>
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        CryptFunction alg = new CryptFunction();

        AES aes = new AES();
        aes.genarateKey();
        SecretKey aeskey = aes.getkey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Digest digest = new Digest();

        String plaintext = "Hello Alex !!!"; //Plaintext
        System.out.println("Org  Plain:" + alg.toHexString(plaintext.getBytes()));
        int plaintextSize = plaintext.getBytes().length; //Plaintext real size
        byte[] keydigest = digest.Calc(aeskey.getEncoded()); // Digest of aes key
        System.out.println("Key digest:" + alg.toHexString(keydigest));

        outputStream.write(keydigest);
        outputStream.write(plaintextSize);
        outputStream.write(plaintext.getBytes());

        byte[] bigplain = outputStream.toByteArray(); //Plaintext with key digest and length in front
        System.out.println("Big  Plain:" + alg.toHexString(bigplain));
        byte[] ciphertext = aes.encrypt(bigplain);
        byte[] dplain = aes.decrypt(ciphertext);//Decrepted plain text
        System.out.println("Decr Plain:" + alg.toHexString(dplain));

    }
}
