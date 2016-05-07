package alexkantas.cryptography.messenger;

import alexkantas.cryptography.algorithms.AES;
import alexkantas.cryptography.algorithms.RSA;
import alexkantas.cryptography.functions.CryptFunction;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Alexandros Kantas
 */
public class Client_RSA {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        String ip = "localhost";
        int portNumber = 4433;
        AES aes = new AES();
        RSA rsa = new RSA();
        Cheat.ClientPublic = rsa.getKeypair().getPublic();
        Cheat.ClientPrivate = rsa.getKeypair().getPrivate();
        PublicKey publicKey = Cheat.ClientPublic;
        PublicKey privateKey = (PublicKey) Cheat.serverPrivate;
        PublicKey serverPublic =Cheat.serverPublic ;
        String key = "414C4558414E44524F53204B414E54415320416C6578204B616E746173202041";
        CryptFunction alg = new CryptFunction();

        try (
                Socket mySocket = new Socket(ip, portNumber);
                PrintWriter out = new PrintWriter(mySocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(mySocket.getInputStream()));) {

            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            String fromServer, fromServerDecrypted,c;
            String fromUser, fromUserEncrypted;
            byte[] m;

            System.out.println("Client run");
            while(true){
                if((c = in.readLine()) != null){
                m =rsa.decrypt(rsa.decrypt(c.getBytes(),serverPublic),privateKey);
                aes.setkey(alg.toHexString(m));
                break;
            }
            }
            while ((fromServer = in.readLine()) != null) {
                fromServerDecrypted = aes.decrypt(fromServer);
                fromServerDecrypted = alg.hexToASCII(fromServerDecrypted);
                System.out.println("Server: " + fromServerDecrypted);
                if (fromServerDecrypted.equals("OFF.")) {
                    break;
                }

                fromUser = stdIn.readLine();
                fromUserEncrypted = aes.encrypt(fromUser);
                if (fromUser != null) {
                    System.out.println("Client: " + fromUser);
                    out.println(fromUserEncrypted);
                }

            }
        } catch (IOException ex) {
            System.err.println("Couldn't get I/O for the connection to " + ip);
            System.exit(1);
        }

    }
}