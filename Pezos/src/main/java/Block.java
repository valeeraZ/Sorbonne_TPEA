import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
@Data
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
        byte[] res;
        res = ArrayUtils.addAll(level.toBytesFromInformation(), hashPredecessor);
        res = ArrayUtils.addAll(res, timestamp);
        res = ArrayUtils.addAll(res, hashOperations);
        res = ArrayUtils.addAll(res, hashState);
        res = ArrayUtils.addAll(res, signature);
        return res;
    }

    private boolean verifyHashPredecessor(TCPClient client){
        //TODO
        return false;
    }

    private boolean verifyTimestamp(TCPClient client){
        //TODO
        return false;
    }

    /**
     * @author Wenzhuo ZHAO
     * verify the hash list of operations
     * @param client TCPClient to get more information of previous block
     * @return true if this operation is incorrect
     */
    private boolean verifyHashOperations(TCPClient client){
        //TODO
        return false;
    }

    private boolean verifyHashState(TCPClient client){
        //TODO
        return false;
    }

    private boolean verifySignature(TCPClient client){
        //TODO
        return false;
    }

    /**
     * search for the bad operations in a block, then sign these operations
     * @param client TCPClient if needed to get more information of previous block
     * @return a List of SignedOperation containing the signed operations
     */
    public List<SignedOperation> verifyOperations(TCPClient client) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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
                "timestamp: " + new Timestamp(Utils.decodeLong(timestamp)).toString() + "\n" +
                "hashOperations: " + DatatypeConverter.printHexBinary(hashOperations) + "\n" +
                "hashState: " + DatatypeConverter.printHexBinary(hashState) + "\n" +
                "signature: " + DatatypeConverter.printHexBinary(signature);
    }
}
