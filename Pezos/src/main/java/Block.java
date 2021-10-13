import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.sql.Timestamp;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public class Block implements Information{
    private final byte[] level;
    private final byte[] hashPredecessor;
    private final byte[] timestamp;
    private final byte[] hashOperations;
    private final byte[] hashState;
    private final byte[] signature;

    public Block(byte[] level, byte[] hashPredecessor, byte[] timestamp, byte[] hashOperations, byte[] hashState, byte[] signature) {
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
        byte[] level = ArrayUtils.subarray(info, 0, 4);
        byte[] hashPredecessor = ArrayUtils.subarray(info, 4, 36);
        byte[] timestamp = ArrayUtils.subarray(info, 36, 44);
        byte[] hashOperations = ArrayUtils.subarray(info, 44, 76);
        byte[] hashState = ArrayUtils.subarray(info, 76, 108);
        byte[] signature = ArrayUtils.subarray(info, 108, 172);
        return new Block(level, hashPredecessor, timestamp, hashOperations, hashState, signature);
    }

    public byte[] toBytesFromInformation(){
        return null;
    }

    @Override
    public String toString() {
        return  "BLOCK \n" +
                "level: " + Utils.decodeInt(level) + "\n" +
                "hashPredecessor: " + DatatypeConverter.printHexBinary(hashPredecessor) + "\n" +
                "timestamp: " + new Timestamp(Utils.decodeLong(timestamp)).toString() + "\n" +
                "hashOperations: " + DatatypeConverter.printHexBinary(hashOperations) + "\n" +
                "hashState: " + DatatypeConverter.printHexBinary(hashState) + "\n" +
                "signature: " + DatatypeConverter.printHexBinary(signature) + "\n" ;
    }
}
