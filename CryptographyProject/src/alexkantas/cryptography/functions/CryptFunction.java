package alexkantas.cryptography.functions;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Alexandros Kantas
 */
public class CryptFunction {

    /**
     * Converts a byte array to hex string
     *
     * @param block byte array
     * @return HEX DUMP in String
     */
    public String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
//            if (i < len - 1) {
//                buf.append(":");
//            }
        }
        return buf.toString();
    }

    /**
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /**
     * Converts a hex string to ASCII
     *
     * @param hexValue Hex string
     * @return converted string
     */
    public String hexToASCII(String hexValue) {
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexValue.length(); i += 2) {
            String str = hexValue.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * Converts a hex string to byte array
     *
     * @param s hex string
     * @return byte array
     */
    public byte[] fromHexString(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public PrivateKey stringToPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyData = DatatypeConverter.parseHexBinary(key);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = (PrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(keyData));
        return privateKey;
    }

    public PublicKey stringToPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyData = DatatypeConverter.parseHexBinary(key);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = (PublicKey) factory.generatePublic(new PKCS8EncodedKeySpec(keyData));
        return publicKey;
    }

}
