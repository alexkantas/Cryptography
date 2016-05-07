package alexkantas.cryptography.messenger;

import alexkantas.cryptography.algorithms.AES;
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
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Alexandros Kantas
 */
public class ServerAES {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int portNumber = 4433;
        AES aes = new AES();
        String key = "414C4558414E44524F53204B414E54415320416C6578204B616E746173202041";
        CryptFunction alg = new CryptFunction();

        try ( //Using try-with-resources statement
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));) {

            String inputLine, outputLine,decryptedinput,encryptedoutput;
            aes.setkey(key);
            System.out.println("Server Running"); //Run server logic
            out.println(aes.encrypt("ON."));
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
