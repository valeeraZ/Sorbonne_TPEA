import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.commons.lang3.ArrayUtils;
import org.kocakosm.jblake2.Blake2b;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
@Data
@Slf4j
public class Block implements Information{
    private final Level level;
    private final byte[] hashPredecessor;
    private final byte[] timestamp;
    private final byte[] hashOperations;
    private final byte[] hashState;
    private final byte[] signature;

    public Block(Level level, byte[] hashPredecessor, byte[] timestamp, byte[] hashOperations, byte[] hashState, byte[] signature) {
        this.level = level;
        this.hashPredecessor = hashPredecessor;
        this.timestamp = timestamp;
        this.hashOperations = hashOperations;
        this.hashState = hashState;
        this.signature = signature;
    }

    /**
     * from a byte[174] to block
     * @param info the byte array of a block
     * @return a Block (returned by server)
     */
    public static Block fromBytesToInformation(byte[] info){
        if (info.length != 172)
            throw new RuntimeException("Bad Information of Block");
        Level level = Level.fromBytesToInformation(ArrayUtils.subarray(info, 0, 4));
        byte[] hashPredecessor = ArrayUtils.subarray(info, 4, 36);
        byte[] timestamp = ArrayUtils.subarray(info, 36, 44);
        byte[] hashOperations = ArrayUtils.subarray(info, 44, 76);
        byte[] hashState = ArrayUtils.subarray(info, 76, 108);
        byte[] signature = ArrayUtils.subarray(info, 108, 172);
        return new Block(level, hashPredecessor, timestamp, hashOperations, hashState, signature);
    }

    /**
     * from (Block)Information to bytes
     * @return a byte array
     */
    public byte[] toBytesFromInformation(){
        return Utils.mergeArrays(level.toBytesFromInformation(),
                hashPredecessor,
                timestamp,
                hashOperations,
                hashState,
                signature);
    }

    /**
     * @author Chengyu YANG
     * verify the hash predecessor
     * @param client TCPClient to get more information of previous block
     * @return true if the hash of predecessor is correct
     */
    public boolean verifyHashPredecessor(TCPClient client) throws IOException {
        Message get_block_pre = new Message(Application.GET_BLOCK.setInformation(new Level(level.getLevel()-1)));
        client.sendMessage(get_block_pre);
        byte[] info_pre = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_pre = client.receiveBytes(info_pre);
        Application blockInfo_pre = Application.fromBytesToApplication(info_pre);
        log.info("Receive Block information: \n" + blockInfo_pre);
        assert blockInfo_pre != null;
        Block block_pre = (Block) blockInfo_pre.getInformation();

        Blake2b b2 = new Blake2b(32);
        b2.update(block_pre.toBytesFromInformation());
        byte[] hash_pre = b2.digest();
        System.out.println("hash pre in this: "+DatatypeConverter.printHexBinary(hashPredecessor));
        System.out.println("hash predecessor: "+DatatypeConverter.printHexBinary(hash_pre));
        return Arrays.equals(hashPredecessor,hash_pre);
    }

    /**
     * @author Chengyu YANG
     * verify the timestamp
     * @param client TCPClient to get more information of previous block
     * @return true if this timestamp is correct
     */
    public boolean verifyTimestamp(TCPClient client) throws IOException, ParseException {
        Message get_block_pre = new Message(Application.GET_BLOCK.setInformation(new Level(level.getLevel()-1)));
        client.sendMessage(get_block_pre);
        byte[] info_pre = new byte[Constants.TAG_SIZE + Constants.BLOCK_SIZE];
        info_pre = client.receiveBytes(info_pre);
        Application blockInfo_pre = Application.fromBytesToApplication(info_pre);
        log.info("Receive Block information: \n" + blockInfo_pre);
        assert blockInfo_pre != null;
        Block block_pre = (Block) blockInfo_pre.getInformation();
        Timestamp time_pred = new Timestamp(Utils.decodeLong(block_pre.getTimestamp())*1000);
        Timestamp time_now = new Timestamp(Utils.decodeLong(timestamp)*1000);
        //System.out.println(Arrays.toString(block_pre.getTimestamp()));
        //System.out.println(Arrays.toString(timestamp));
        SimpleDateFormat sdf =new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        long timePre= sdf.parse(time_pred.toString()).getTime();
        long timeNow = sdf.parse(time_now.toString()).getTime();
        //System.out.println(time_pred);
        //System.out.println(time_now);
        //System.out.println(timeNow-timePre);
        return (timeNow-timePre)/1000/60 >= 10;
    }

    /**
     * @author Wenzhuo ZHAO
     * verify the hash list of operations
     * @param client TCPClient to get more information of previous block
     * @return true if this operation is incorrect
     */
    public boolean verifyHashOperations(TCPClient client) throws IOException {
        Level level = getLevel();
        Message get_ops = new Message(Application.GET_BLOCK_OPERATIONS.setInformation(level));
        client.sendMessage(get_ops);
        byte[] ops = new byte[Constants.TAG_SIZE*2 + Constants.MAX_SIGNED_OPS_SIZE];
        ops = client.receiveBytes(ops);
        Application block_ops = Application.fromBytesToApplication(ops);
        log.info("Receive Block " + level + "'s operations: \n" + block_ops);
        assert block_ops != null;
        SignedOperations operations = (SignedOperations) block_ops.getInformation();
        List<SignedOperation> listOperations = operations.getSignedOperations();

        byte[] correction = opsHash(listOperations);
        // delete the comments for testing
        //log.info("Block " + level + "'s correct hashOperations is " + DatatypeConverter.printHexBinary(correction));
        return Arrays.equals(hashOperations, correction);
    }

    /**
     * calculation of hash list of operations
     * @param listOperations operations
     * @return hash list of operations
     */
    private byte[] opsHash(List<SignedOperation> listOperations){
        Blake2b b2 = new Blake2b(32);
        if (listOperations.isEmpty())
            return new byte[Constants.HASH_SIZE];
        if (listOperations.size() == 1){
            b2.update(listOperations.get(0).toBytesFromInformation());
            return b2.digest();
        }
        SignedOperation lastOp = listOperations.remove(listOperations.size() - 1);
        b2.update(opsHash(listOperations));

        Blake2b b2_1 = new Blake2b(32);
        b2_1.update(lastOp.toBytesFromInformation());
        byte[] hash_last_op = b2_1.digest();

        b2.update(hash_last_op);
        return b2.digest();
    }

    /**
     * @author Zhaojie LU
     * @return true if this Hashstate is incorrect
     */
    public boolean verifyHashState(TCPClient client) throws IOException{
            Level level = this.getLevel();
            Message get_state = new Message(Application.GET_STATE.setInformation(level));
            client.sendMessage(get_state);
            byte[] state = new byte[Constants.STATE_SIZE];
            state = client.receiveBytes(state);
            Application state_app = Application.fromBytesToApplication(state);
            byte[] state_byte = state_app.getInformation().toBytesFromInformation();
            Blake2b b2 = new Blake2b(32);
            b2.update(state_byte);
            byte[] hash_state = b2.digest();
            byte[] correction = this.hashState;
            log.info("hash_state" + Arrays.toString(hash_state) + "\n" );
            log.info("hash_state_from_block" + Arrays.toString(correction) + "\n" );
        return Arrays.equals(hash_state, correction);
    }
    /**
     * @author Zhen HOU
     * @return verification of the signature
     */
    private boolean verifySignature(TCPClient client){
        try{
            byte[] publicKeyDictateur = DatatypeConverter.parseHexBinary(Constants.PUBLIC_KEY); //obtenir par getKeyPublicState
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
            EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyDictateur, spec);
            PublicKey pk_dic = new EdDSAPublicKey(publicKeySpec);

            //byte[] bloc_encode = ArrayUtils.subarray(info, 0, 108);
            byte[] bloc_encode = Utils.mergeArrays(level.toBytesFromInformation(), hashPredecessor, timestamp, hashOperations, hashState);
            Blake2b b2 = new Blake2b(32);
            b2.update(bloc_encode);
            byte[] hash_bloc = b2.digest();

            boolean res = ED25519.verify(pk_dic,hash_bloc,signature);
            //byte[] signature_dic = ED25519.sign(keyPair, hash_seed);
            return res;

        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    /**
     * search for the bad operations in a block, then sign these operations
     * @param client TCPClient if needed to get more information of previous block
     * @return a List of SignedOperation containing the signed operations
     */
    public List<SignedOperation> verifyOperations(TCPClient client) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, ParseException {
        List<SignedOperation> errors = new ArrayList<>();
        if (verifyTimestamp(client)){
            Operation op = Operation.BAD_TIMESTAMP.setError(timestamp);// only BAD SIGNATURE doesn't need to set error
            byte[] signatureTimestamp = ED25519.sign(client.getKeyPair(), timestamp);
            SignedOperation signedOperation = new SignedOperation(op, Constants.PUBLIC_KEY_BYTES, signatureTimestamp);
            errors.add(signedOperation);
        }
        //TODO the rest 4
        return errors;
    }

    @Override
    public String toString() {
        return  "level: " + level + "\n" +
                "hashPredecessor: " + DatatypeConverter.printHexBinary(hashPredecessor) + "\n" +
                "timestamp: " + new Timestamp(Utils.decodeLong(timestamp)*1000) + "\n" +
                "hashOperations: " + DatatypeConverter.printHexBinary(hashOperations) + "\n" +
                "hashState: " + DatatypeConverter.printHexBinary(hashState) + "\n" +
                "signature: " + DatatypeConverter.printHexBinary(signature);
    }
}
