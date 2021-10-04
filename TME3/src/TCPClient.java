import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * Created by Wenzhuo Zhao on 04/10/2021.
 */
public class TCPClient {
    private final Socket socket;

    private final PrintWriter pw;
    private final BufferedReader br;

    public TCPClient(String ip, String port) throws IOException {
        socket = new Socket(ip, Integer.parseInt(port));

        OutputStream socketOut = socket.getOutputStream();
        pw = new PrintWriter(new OutputStreamWriter(socketOut, StandardCharsets.UTF_8), true);

        InputStream socketIn = socket.getInputStream();
        br = new BufferedReader(new InputStreamReader(socketIn, StandardCharsets.UTF_8));

    }

    public void send(String msg) {
        pw.println(msg);
    }

    public String receive() {
        String msg = null;
        try {
            msg = br.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return msg;
    }

    public void close() {
        try {
            if (socket != null)
                socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void action(KeyPair keyPair) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        InputStream in = socket.getInputStream();
        ObjectInputStream inStream = new ObjectInputStream(in);

        OutputStream out = socket.getOutputStream();
        ObjectOutputStream outStream = new ObjectOutputStream(out);

        outStream.writeObject(keyPair.getPublic());

        // message of response of checking public key
        System.out.println(receive());

        // message of 128 bytes data to sign
        byte[] msg = receive().getBytes();

        byte[] signature = ED25519.sign(keyPair, msg);

        send(Arrays.toString(signature));

        // message of response of checking signature: ok or ko
        System.out.println(receive());
    }
}
