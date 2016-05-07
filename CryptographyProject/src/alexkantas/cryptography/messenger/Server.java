package alexkantas.cryptography.messenger;

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
public class Server {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int portNumber = 4433;

        try ( //Using try-with-resources statement
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));) {

            String inputLine, outputLine;
            System.out.println("Server Running"); //Run server logic
            out.println("ON.");
            while ((inputLine = in.readLine()) != null) {
                if (inputLine.equals("OFF.")) {
                    break;
                }
                System.out.println("Server receive : " + inputLine);
                System.out.println("type message :");
                outputLine = stdIn.readLine();
                out.println(outputLine);
            }

        }
    }

}
