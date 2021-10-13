import lombok.extern.slf4j.Slf4j;
import org.kocakosm.jblake2.Blake2b;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.List;

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

    public KeyPair getKeyPair() {
        return keyPair;
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

    public void sendMessage(Message message) throws IOException {
        out.write(message.toBytesOfMsg());
    }

    /**
     * authentication procedure
     * @return a current head block if client passed the authentication protocole
     */
    public Application authentication() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // a random seed of 24b from server
        byte[] seed = new byte[24];
        int len_seed = in.read(seed);
        if (len_seed == 0){
            log.warn("Please check the configuration of connection");
            return null;
        }
        log.info("Receive Seed: \n" + DatatypeConverter.printHexBinary(seed));

        // send authentication message
        byte[] publicKey = DatatypeConverter.parseHexBinary(Constants.PUBLIC_KEY);
        Message publicKeyMessage = new Message(publicKey);
        sendMessage(publicKeyMessage);
        log.info("Send Public Key: \n" + publicKeyMessage.toHexString());

        // hash the seed, and send the signature of the hash
        Blake2b b2 = new Blake2b(32);
        b2.update(seed);
        byte[] hash_seed = b2.digest();
        byte[] signature = ED25519.sign(keyPair, hash_seed);
        Message signatureMessage = new Message(signature);
        sendMessage(signatureMessage);
        log.info("Send Signature: \n" + signatureMessage.toHexString());

        // send GET CURRENT HEAD message
        Message getHead = new Message(Application.GET_CURRENT_HEAD);
        sendMessage(getHead);
        log.info("Send Message: \n" + Application.GET_CURRENT_HEAD + " - " + getHead.toHexString());

        byte[] info = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        int len = in.read(info);
        Application block = null;
        if (len > 0){
            block = Application.fromBytesToApplication(info);
            log.info("Receive Block information: \n" + block);
        }

        return block;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException{
        TCPClient client = new TCPClient(Constants.IP, Constants.PORT);
        Block block;
        Application info = client.authentication();
        if (info != null){
            log.info("Authentication success");
            block = (Block) info.getInformation();
        }else {
            log.warn("Authentication failure, please check your KeyPair");
            return;
        }

        /*
        List<SignedOperation> correction = block.verifyOperations(client);
        for (SignedOperation op: correction) {
            Application inject = Application.INJECT_OPERATION;
            inject.setInformation(op);
            Message injection = new Message(inject);
            client.sendMessage(injection);
        }
        */

    }
}