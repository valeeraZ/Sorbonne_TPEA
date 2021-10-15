import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Created by Wenzhuo Zhao on 11/10/2021.
 */
@Slf4j
public class ApplicationTest {

    @Test
    public void generateKeyPairTest() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair = ED25519.prepareKeyPair();
        byte[] seed = DatatypeConverter.parseHexBinary("B12792B9DFE0E5610649827AEAFC241FE467854B5E5BA1DE");
        byte[] signature = ED25519.sign(keyPair, seed);
        assert ED25519.verify(keyPair.getPublic(), seed, signature);
    }

    @Test
    public void connectionTest() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException {
        TCPClient client = new TCPClient(Constants.IP, Constants.PORT);
        assert client.authentication() != null;
    }

    @Test
    public void blockOperationsTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        TCPClient client = new TCPClient(Constants.IP, Constants.PORT);
        Application info = client.authentication();
        assert info != null;
        Block block = (Block) info.getInformation();
        Level level = block.getLevel();
        Message get_ops = new Message(Application.GET_BLOCK_OPERATIONS.setInformation(level));
        client.sendMessage(get_ops);
        byte[] ops = new byte[Constants.TAG_SIZE*2 + Constants.MAX_SIGNED_OPS_SIZE];
        ops = client.receiveBytes(ops);
        //log.info(DatatypeConverter.printHexBinary(ops));
        Application block_ops = Application.fromBytesToApplication(ops);
        log.info("Receive Block " + level + "'s operations: \n" + block_ops);
    }
}
