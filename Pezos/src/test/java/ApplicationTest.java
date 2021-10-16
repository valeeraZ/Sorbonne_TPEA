import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.Assert.assertTrue;

/**
 * Created by Wenzhuo Zhao on 11/10/2021.
 */
@Slf4j
public class ApplicationTest {
    private TCPClient client;
    private Block block;

    @Before
    public void generateKeyPairTest() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair = ED25519.prepareKeyPair();
        byte[] seed = DatatypeConverter.parseHexBinary("B12792B9DFE0E5610649827AEAFC241FE467854B5E5BA1DE");
        byte[] signature = ED25519.sign(keyPair, seed);
        assert ED25519.verify(keyPair.getPublic(), seed, signature);
    }

    @Before
    public void connectionTest() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException {
        client = new TCPClient(Constants.IP, Constants.PORT);
        Application info = client.authentication();
        assert info != null;
        block = (Block) info.getInformation();
    }

    @Test
    public void convertBytesTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        byte[] encode = block.toBytesFromInformation();
        Block newBlock = Block.fromBytesToInformation(encode);
        assert block.canEqual(newBlock);
    }

    @Test
    public void blockOperationsTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Level level = block.getLevel();
        Message get_ops = new Message(Application.GET_BLOCK_OPERATIONS.setInformation(level));
        client.sendMessage(get_ops);
        byte[] ops = new byte[Constants.TAG_SIZE*2 + Constants.MAX_SIGNED_OPS_SIZE];
        ops = client.receiveBytes(ops);
        //log.info(DatatypeConverter.printHexBinary(ops));
        Application block_ops = Application.fromBytesToApplication(ops);
        log.info("Receive Block " + level + "'s operations: \n" + block_ops);
    }

    @Test
    /*
     * in block 711, there's no BAD OPERATIONS HASH injected
     * therefore the hashOperations given by block 710 is correct
     * so we can test
     * the hashOperations we calculate for 710 should be equal to the hashOperations given in 710
     * and we can see
     * the hash of operations we calculate for 709 should be equal to the 710's BAD OPERATIONS HASH's contenu
     */
    public void hashOperationsTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Level level_711 = new Level(711);
        Message get_block_711 = new Message(Application.GET_BLOCK.setInformation(level_711));
        client.sendMessage(get_block_711);
        byte[] info_711 = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_711 = client.receiveBytes(info_711);
        Application blockInfo_711 = Application.fromBytesToApplication(info_711);
        log.info("Receive Block information: \n" + blockInfo_711);
        assert blockInfo_711 != null;
        Block block_711 = (Block) blockInfo_711.getInformation();

        Level level_710 = new Level(710);
        Message get_block_710 = new Message(Application.GET_BLOCK.setInformation(level_710));
        client.sendMessage(get_block_710);
        byte[] info_710 = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_710 = client.receiveBytes(info_710);
        Application blockInfo_710 = Application.fromBytesToApplication(info_710);
        log.info("Receive Block information: \n" + blockInfo_710);
        assert blockInfo_710 != null;
        Block block_710 = (Block) blockInfo_710.getInformation();

        assertTrue(block_710.verifyHashOperations(client));

        Level level_709 = new Level(709);
        Message get_block_709 = new Message(Application.GET_BLOCK.setInformation(level_709));
        client.sendMessage(get_block_709);
        byte[] info_709 = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_709 = client.receiveBytes(info_709);
        Application blockInfo_709 = Application.fromBytesToApplication(info_709);
        log.info("Receive Block information: \n" + blockInfo_709);
        assert blockInfo_709 != null;
        Block block_709 = (Block) blockInfo_709.getInformation();
        block_709.verifyHashOperations(client);

    }


    @Test
    public void BLOCK_STATE_Test() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Level level = block.getLevel();
        Message get_state = new Message(Application.GET_STATE.setInformation(level));
        client.sendMessage(get_state);
        byte[] state = new byte[Constants.STATE_SIZE];
        state = client.receiveBytes(state);
        Application block_ops = Application.fromBytesToApplication(state);
        log.info("Receive state " + level + "'s operations: \n" + block_ops);
    }

    @Test
    public void StateVerification() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException{
        Level level_711 = new Level(711);
        Message get_block_711 = new Message(Application.GET_BLOCK.setInformation(level_711));
        client.sendMessage(get_block_711);
        byte[] info_711 = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_711 = client.receiveBytes(info_711);
        Application blockInfo_711 = Application.fromBytesToApplication(info_711);
        log.info("Receive Block information: \n" + blockInfo_711);
        assert blockInfo_711 != null;
        Block block_711 = (Block) blockInfo_711.getInformation();

        //boolean b = block.verifyHashState(client);
        boolean b = block_711.verifyHashState(client);
        log.info("verification_state:" + b);
    }
}
