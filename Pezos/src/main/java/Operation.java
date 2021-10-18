import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.sql.Timestamp;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public class Operation{
    private OperationType type;
    private byte[] error;

    public Operation(OperationType type, byte[] error) {
        this.type = type;
        this.error = error;
    }

    // Signature doesn't have error
    public Operation(OperationType type) {
        this.type = type;
    }

    public static Operation fromBytesToInformation(byte[] app){
        short tag = Utils.decodeShort(ArrayUtils.subarray(app, 0, 2));
        byte[] info = ArrayUtils.subarray(app, 2, app.length);
        switch (tag){
            case 1:
                return new Operation(OperationType.BAD_PREDECESSOR, info);
            case 2:
                return new Operation(OperationType.BAD_TIMESTAMP, info);
            case 3:
                return new Operation(OperationType.BAD_OPERATIONS_HASH, info);
            case 4:
                return new Operation(OperationType.BAD_CONTEXT_HASH, info);
            case 5:
                return new Operation(OperationType.BAD_SIGNATURE, info);
            default:
                throw new RuntimeException("Bad Tag, cannot analyse this operation");
        }
    }

    public byte[] toBytesFromOperation(){
        // only BAD SIGNATURE doesn't need to declare explicitly the error
        if (error != null)
            return ArrayUtils.addAll(type.toBytesFromOperation(), error);
        return type.toBytesFromOperation();
    }

    public String toString(){
        if (error == null)
            return type.tag + " - " + type.name;

        if (type.tag == 2)
            return type.tag + " - " + type.name + ": \n" + new Timestamp(Utils.decodeLong(error)*1000);

        return type.tag + " - " + type.name + ": \n" + DatatypeConverter.printHexBinary(error);
    }
}


enum OperationType {
    BAD_PREDECESSOR((short)1, "BAD PREDECESSOR"),
    BAD_TIMESTAMP((short)2, "BAD TIMESTAMP"),
    BAD_OPERATIONS_HASH((short)3, "BAD OPERATIONS HASH"),
    //literally, context means state of a block
    BAD_CONTEXT_HASH((short)4, "BAD CONTEXT HASH"),
    BAD_SIGNATURE((short)5, "BAD SIGNATURE");

    public final short tag;
    public final String name;

    OperationType(short tag, String name) {
        this.tag = tag;
        this.name = name;
    }

    public byte[] toBytesFromOperation(){
        return Utils.encodeShort(tag);
    }

}
