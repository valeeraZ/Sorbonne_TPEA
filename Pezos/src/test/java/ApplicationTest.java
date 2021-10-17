import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.List;

import static org.junit.Assert.*;

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
        assertTrue(ED25519.verify(keyPair.getPublic(), seed, signature));
    }

    @Before
    public void connectionTest() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InterruptedException {
        client = new TCPClient(Constants.IP, Constants.PORT);
        Application info = client.authentication();
        assert info != null;
        block = (Block) info.getInformation();
        assertNotNull(block);
    }

    @Test
    public void convertBytesTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        byte[] encode = block.toBytesFromInformation();
        Block newBlock = Block.fromBytesToInformation(encode);
        assertTrue(block.canEqual(newBlock));
    }

    @Test
    public void getBlockOperationsTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Level level = block.getLevel();
        Message get_ops = new Message(Application.GET_BLOCK_OPERATIONS.setInformation(level));
        client.sendMessage(get_ops);
        byte[] ops = new byte[Constants.TAG_SIZE*2 + Constants.MAX_SIGNED_OPS_SIZE];
        ops = client.receiveBytes(ops);
        //log.info(DatatypeConverter.printHexBinary(ops));
        Application block_ops = Application.fromBytesToApplication(ops);
        log.info("Receive Block " + level + "'s operations: \n" + block_ops);
        assertNotNull(block_ops);
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
    public void verifyHashOperationsTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Block block_711 = Block.getBlockByLevel(new Level(711), client);
        block_711.verifyHashOperations(client);

        Block block_710 = Block.getBlockByLevel(new Level(710), client);
        assertTrue(block_710.verifyHashOperations(client));

        Block block_709 = Block.getBlockByLevel(new Level(709), client);
        assertFalse(block_709.verifyHashOperations(client));
    }

    @Test
    public void verifyTimeStampTest() throws IOException, ParseException {
        Block block_849 = Block.getBlockByLevel(new Level(849), client);
        assertTrue(block_849.verifyTimestamp(client));

        Block block_848 = Block.getBlockByLevel(new Level(848), client);
        assertFalse(block_848.verifyTimestamp(client));
    }

    @Test
    public void getBlockStateTest() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        assertNotNull(block.getState(client));
    }

    @Test
    public void verifyHashStateTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException{
        Block block_711 = Block.getBlockByLevel(new Level(711), client);
        assertTrue(block_711.verifyHashState(client));
    }


    @Test
    public void verifyHashPredecessorTest() throws IOException{
        Block block_712 = Block.getBlockByLevel(new Level(712), client);
        block_712.verifyHashOperations(client);

        Block block_711 = Block.getBlockByLevel(new Level(711), client);
        assertFalse(block_711.verifyHashPredecessor(client));

        Block block_710 = Block.getBlockByLevel(new Level(710), client);
        assertTrue(block_710.verifyHashPredecessor(client));
        //C18CD4CB966FD56A11D3BECDF533D94B944F38E91B889AEE3D091FE7A22BDC87
    }

    @Test
    public void verifySignatureTest() throws IOException {
        Block block_711 = Block.getBlockByLevel(new Level(711), client);
        assertTrue(block_711.verifySignature(client));

        Block block_710 = Block.getBlockByLevel(new Level(710), client);
        assertFalse(block_710.verifySignature(client));
    }

    @Test
    public void verifyOperationsTest() throws IOException, ParseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Block block_710 = Block.getBlockByLevel(new Level(710), client);
        List<SignedOperation> corrections = block_710.verifyOperations(client);
        log.info("Corrections Injected in Block 710: " + corrections);

        Level level = new Level(711);
        Message get_ops = new Message(Application.GET_BLOCK_OPERATIONS.setInformation(level));
        client.sendMessage(get_ops);
        byte[] ops = new byte[Constants.TAG_SIZE*2 + Constants.MAX_SIGNED_OPS_SIZE];
        ops = client.receiveBytes(ops);
        //log.info(DatatypeConverter.printHexBinary(ops));
        Application block_ops = Application.fromBytesToApplication(ops);
        log.info("Receive Block " + level + "'s operations: \n" + block_ops);

    }

}