import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;

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
    // error could be byte[] of hash predecessor, timestamp... all 5 kinds
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

    @Override
    public String toString() {
        if (error == null)
            return tag + " - " + name;

        if (tag == 2)
            return tag + " - " + name + " error: \n" + Utils.decodeShort(error);

        return tag + " - " + name + " error: \n" + DatatypeConverter.printHexBinary(error);
    }

}
