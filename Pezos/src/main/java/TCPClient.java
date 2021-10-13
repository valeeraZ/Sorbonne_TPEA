import lombok.extern.slf4j.Slf4j;
import org.kocakosm.jblake2.Blake2b;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.*;

/**
 * Created by Wenzhuo Zhao on 11/10/2021.
 */
@Slf4j
public class TCPClient {
    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final KeyPair keyPair;

    public TCPClient(String ip, String port) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        socket = new Socket(ip, Integer.parseInt(port));
        in = socket.getInputStream();
        out = socket.getOutputStream();
        keyPair = ED25519.prepareKeyPair();
    }

    /**
     * close the socket
     */
    public void close() {
        try {
            if (socket != null)
                socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte[] readAllBytes(InputStream inputStream) throws IOException {
        byte[] buf = new byte[300];
        int readLen;
        IOException exception = null;

        try {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                while ((readLen = inputStream.read(buf, 0, 300)) != -1)
                    outputStream.write(buf, 0, readLen);

                return outputStream.toByteArray();
            }
        } catch (IOException e) {
            exception = e;
            throw e;
        } finally {
            if (exception == null) inputStream.close();
            else try {
                inputStream.close();
            } catch (IOException e) {
                exception.addSuppressed(e);
            }
        }
    }

    /**
     * authentication procedure
     * @return true if client passed the authentication protocole
     */
    public boolean authentication() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // a random seed of 24b from server
        byte[] seed = new byte[24];
        in.read(seed);
        log.info("Receive Seed: \n" + DatatypeConverter.printHexBinary(seed));

        // send authentication message
        byte[] publicKey = DatatypeConverter.parseHexBinary(Constants.PUBLIC_KEY);
        Message publicKeyMessage = new Message(publicKey);
        out.write(publicKeyMessage.toBytesOfMsg());
        log.info("Send Public Key: \n" + publicKeyMessage.toHexString());

        // hash the seed, and send the signature of the hash
        Blake2b b2 = new Blake2b(32);
        b2.update(seed);
        byte[] hash_seed = b2.digest();
        byte[] signature = ED25519.sign(keyPair, hash_seed);
        Message signatureMessage = new Message(signature);
        out.write(signatureMessage.toBytesOfMsg());
        log.info("Send Signature: \n" + signatureMessage.toHexString());

        // send GET CURRENT HEAD message
        Message getHead = new Message(Application.GET_CURRENT_HEAD);
        out.write(getHead.toBytesOfMsg());
        log.info("Send Message: \n" + Application.GET_CURRENT_HEAD + " - " + getHead.toHexString());

        byte[] info = new byte[174];
        int len = in.read(info);
        if (len > 0)
            log.info("Receive Block information: \n" + Application.fromBytesToApplication(info));

        return len > 0;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException{
        TCPClient client = new TCPClient(Constants.IP, Constants.PORT);
        if (client.authentication())
            log.info("Authentication success");
        else return;
    }
}