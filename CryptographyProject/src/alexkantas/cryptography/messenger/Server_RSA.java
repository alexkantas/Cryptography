package alexkantas.cryptography.messenger;

import alexkantas.cryptography.algorithms.AES;
import alexkantas.cryptography.algorithms.RSA;
import alexkantas.cryptography.functions.CryptFunction;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Alexandros Kantas
 */
public class Server_RSA {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int portNumber = 4433;
        RSA rsa = new RSA();
        AES aes = new AES();
        Cheat.serverPublic = rsa.getKeypair().getPublic();
        Cheat.serverPrivate = rsa.getKeypair().getPrivate();
        PublicKey publicKey = Cheat.serverPublic;
        PublicKey privateKey = (PublicKey) Cheat.ClientPrivate;
        PrivateKey clientPublic = (PrivateKey)Cheat.ClientPublic;
        SecretKey AESkey = aes.getkey();
        CryptFunction alg = new CryptFunction();

        try ( //Using try-with-resources statement
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));) {

            String inputLine, outputLine,decryptedinput,encryptedoutput;
            
            System.out.println("Server Running"); //Run server logic
            aes.setkey(AESkey);
//            byte[] m = rsa.encrypt(rsa.encrypt(AESkey.getEncoded(), privateKey),clientPublic);
//            out.println(alg.toHexString(m));
            while ((inputLine = in.readLine()) != null) {
                decryptedinput = aes.decrypt(inputLine);
                decryptedinput = alg.hexToASCII(decryptedinput);
                if (decryptedinput.equals("OFF.")) {
                    break;
                }
                System.out.println("Server receive : " + decryptedinput);
                System.out.println("type message :");
                outputLine = stdIn.readLine();
                encryptedoutput = aes.encrypt(outputLine);
                out.println(encryptedoutput);
            }

        }
    }

}
