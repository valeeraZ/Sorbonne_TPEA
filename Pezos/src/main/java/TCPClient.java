import lombok.extern.slf4j.Slf4j;
import org.kocakosm.jblake2.Blake2b;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.text.ParseException;
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

    /**
     * use OutputStream to send a Message Object, which is converted to byte[] before sending
     * @param message the Message
     */
    public void sendMessage(Message message) throws IOException {
        out.write(message.toBytesOfMsg());
        log.info("Send Message: \n" + message);
    }

    public void sendMessage(Message message, String nameMessage) throws IOException {
        out.write(message.toBytesOfMsg());
        log.info("Send " + nameMessage + ": \n" + message);
    }

    /**
     * use InputStream to read bytes and put in buffer
     * @param buffer the buffer byte array to save bytes
     * @return the buffer containing bytes
     */
    public byte[] receiveBytes(byte[] buffer) throws IOException {
        int len = in.read(buffer);
        if (len < 1)
            throw new RuntimeException("Response not received, please check the connection");
        return buffer;
    }

    /**
     * authentication procedure
     * @return a current head block if client passed the authentication protocole
     */
    public Application authentication() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // a random seed of 24b from server
        byte[] seed = new byte[24];
        seed = receiveBytes(seed);
        log.info("Receive Seed: \n" + DatatypeConverter.printHexBinary(seed));

        // send authentication message
        byte[] publicKey = DatatypeConverter.parseHexBinary(Constants.PUBLIC_KEY);
        Message publicKeyMessage = new Message(publicKey);
        sendMessage(publicKeyMessage, "Public Key");
        //log.info("Send Public Key: \n" + publicKeyMessage);

        // hash the seed, and send the signature of the hash
        Blake2b b2 = new Blake2b(32);
        b2.update(seed);
        byte[] hash_seed = b2.digest();
        byte[] signature = ED25519.sign(keyPair, hash_seed);
        Message signatureMessage = new Message(signature);
        sendMessage(signatureMessage, "Signature");
        //log.info("Send Signature: \n" + signatureMessage);

        // send GET CURRENT HEAD message
        Message getHead = new Message(Application.GET_CURRENT_HEAD);
        sendMessage(getHead);
        //log.info("Send Message: \n" + Application.GET_CURRENT_HEAD + " - " + getHead.toHexString());

        byte[] info = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info = receiveBytes(info);
        Application block = Application.fromBytesToApplication(info);
        log.info("Receive Block information: \n" + block);

        return block;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException, ParseException {
        TCPClient client = new TCPClient(Constants.IP, Constants.PORT);
        Block block;
        Application info = client.authentication();
        if (info != null){
            log.info("\n" + "\033[32;1m"+ "----------Authentication success----------" + "\033[m");
            block = (Block) info.getInformation();
        }else {
            log.warn("Authentication failure, please check your KeyPair");
            return;
        }

        while (!client.socket.isClosed()){
            List<SignedOperation> correction = block.verifyOperations(client);
            for (SignedOperation op: correction) {
                Application inject = Application.INJECT_OPERATION;
                inject.setInformation(op);
                Message injection = new Message(inject);
                client.sendMessage(injection);
            }

            if (block.getState() == null){
                block.setState(block.getState(client));
            }
            for (Account account : block.getState().getAccounts()){
                if (account.getMyAccount()){
                    StringBuilder sb = new StringBuilder();
                    sb.append("\n" + "\033[31;1m"+ "----------Your Account Information----------" + "\n");
                    sb.append(account);
                    sb.append("\n");
                    sb.append("--------------------------------------------" + "\033[m");
                    log.info(sb.toString());
                    break;
                }
            }
            log.info("\n" + "\033[32;1m"+ "Waiting for next block..." + "\033[m");

            byte[] blockInfo = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
            blockInfo = client.receiveBytes(blockInfo);
            info = Application.fromBytesToApplication(blockInfo);
            log.info("Receive Block information: \n" + info);
            if (info == null){
                log.warn("Get Block fail, please check the connection");
                return;
            }
            block = (Block) info.getInformation();
        }

    }
}