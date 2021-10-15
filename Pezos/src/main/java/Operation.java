import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.sql.Timestamp;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public enum Operation {
    BAD_PREDECESSOR((short)1, "BAD PREDECESSOR"),
    BAD_TIMESTAMP((short)2, "BAD TIMESTAMP"),
    BAD_OPERATIONS_HASH((short)3, "BAD OPERATIONS HASH"),
    //literally, context means state of a block
    BAD_CONTEXT_HASH((short)4, "BAD CONTEXT HASH"),
    BAD_SIGNATURE((short)5, "BAD SIGNATURE");

    private final short tag;
    private final String name;
    // error could be byte[] of hash predecessor, timestamp... 4 kinds
    private byte[] error;

    Operation(short tag, String name) {
        this.tag = tag;
        this.name = name;
    }

    public Operation setError(byte[] error){
        this.error = error;
        return this;
    }

    public byte[] toBytesOfMsg(){
        // only BAD SIGNATURE doesn't need to declare explicitly the error
        if (error != null)
            return ArrayUtils.addAll(Utils.encodeShort(tag), error);
        return Utils.encodeShort(tag);
    }

    public static Operation fromBytesToInformation(byte[] app){
        short tag = Utils.decodeShort(ArrayUtils.subarray(app, 0, 2));
        byte[] info = ArrayUtils.subarray(app, 2, app.length);
        switch (tag){
            case 1:
                return Operation.BAD_PREDECESSOR.setError(info);
            case 2:
                return Operation.BAD_TIMESTAMP.setError(info);
            case 3:
                return Operation.BAD_OPERATIONS_HASH.setError(info);
            case 4:
                return Operation.BAD_CONTEXT_HASH.setError(info);
            case 5:
                return Operation.BAD_SIGNATURE;
            default:
                throw new RuntimeException("Bad Tag, cannot analyse this operation");
        }
    }

    @Override
    public String toString() {
        if (error == null)
            return tag + " - " + name;

        if (tag == 2)
            return tag + " - " + name + ": \n" + new Timestamp(Utils.decodeLong(error)).toString();

        return tag + " - " + name + ": \n" + DatatypeConverter.printHexBinary(error);
    }

}
