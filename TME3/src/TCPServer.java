import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by Wenzhuo Zhao on 04/10/2021.
 */
public class TCPServer {
    public final static int port = 8008;
    public final static int length_message = 128;
    private final ServerSocket serverSocket = new ServerSocket(port);
    private final ArrayList<PublicKey> publicKeys;

    public TCPServer(ArrayList<PublicKey> publicKeys) throws IOException {
        this.publicKeys = publicKeys;
        System.out.println("Lance écoute à port " + port);
    }

    private PrintWriter getWriter(Socket socket) throws IOException {
        OutputStream socketOut = socket.getOutputStream();
        return new PrintWriter(new OutputStreamWriter(socketOut, StandardCharsets.UTF_8), true);
    }

    private BufferedReader getReader(Socket socket) throws IOException {
        InputStream socketIn = socket.getInputStream();
        return new BufferedReader(new InputStreamReader(socketIn, StandardCharsets.UTF_8));
    }

    //single user
    public void Service() {
        while (true) {
            Socket socket = null;
            try {
                socket = serverSocket.accept();

                System.out.println("New connection accepted: " + socket.getInetAddress());
                BufferedReader br = getReader(socket);
                PrintWriter pw = getWriter(socket);

                InputStream in = socket.getInputStream();
                ObjectInputStream inStream = new ObjectInputStream(in);

                OutputStream out = socket.getOutputStream();
                ObjectOutputStream outStream = new ObjectOutputStream(out);

                PublicKey publicKey = (PublicKey) inStream.readObject();
                boolean present = publicKeys.stream().anyMatch(pk->pk.equals(publicKey));
                if(!present){
                    pw.println("The public key doesn't match any in this server.");
                    throw new Exception();
                }else {
                    pw.println("Public key existence verified.");
                }

                Random rd = new Random();
                byte[] data = new byte[length_message];
                rd.nextBytes(data);

                pw.println(Arrays.toString(data));

                byte[] signature = br.readLine().getBytes();
                if(ED25519.verify(publicKey, data, signature))
                    pw.println("ok");
                else
                    pw.println("ko");
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    if (socket != null)
                        socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
