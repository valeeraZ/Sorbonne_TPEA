import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public enum Application {
    GET_CURRENT_HEAD((short) 1, "GET CURRENT HEAD"),
    CURRENT_HEAD((short) 2, "CURRENT HEAD"),
    GET_BLOCK((short) 3, "GET BLOCK"),
    BLOCK((short) 4, "BLOCK"),
    GET_BLOCK_OPERATIONS((short) 5, "GET BLOCK OPERATIONS"),
    BLOCK_OPERATIONS((short) 6, "BLOCK OPERATIONS"),
    GET_STATE((short) 7, "GET STATE"),
    BLOCK_STATE((short) 8, "BLOCK STATE"),
    INJECT_OPERATION((short) 9, "INJECT OPERATION");

    private final short tag;
    private final String name;
    private Information information;

    private Application(short tag, String name){
        this.tag = tag;
        this.name = name;
    }

    public Application setInformation(Information information){
        this.information = information;
        return this;
    }

    public byte[] toBytesOfMsg(){
        if (information != null)
            return ArrayUtils.addAll(Utils.encodeShort(tag), information.toBytesFromInformation());
        else
            return Utils.encodeShort(tag);
    }

    public String toHexString(){
        return DatatypeConverter.printHexBinary(toBytesOfMsg());
    }

    public static Application fromBytesToApplication(byte[] app){
        short tag = Utils.decodeShort(ArrayUtils.subarray(app, 0, Constants.TAG_SIZE));
        byte[] info = ArrayUtils.subarray(app, Constants.TAG_SIZE, app.length);
        switch (tag){
            case 1:
                return Application.GET_CURRENT_HEAD;
            case 2:
                Block b2 = Block.fromBytesToInformation(info);
                return Application.CURRENT_HEAD.setInformation(b2);
            case 3:
                Level level3 = Level.fromBytesToInformation(info);
                return Application.GET_BLOCK.setInformation(level3);
            case 4:
                Block b4 = Block.fromBytesToInformation(info);
                return Application.BLOCK.setInformation(b4);
            case 5:
                Level level5 = Level.fromBytesToInformation(info);
                return Application.GET_BLOCK_OPERATIONS.setInformation(level5);
            case 6:
                short sizeOperations = Utils.decodeShort(ArrayUtils.subarray(info, 0, 2));
                SignedOperations operations = SignedOperations.fromBytesToInformation(ArrayUtils.subarray(info, 2, 2+sizeOperations));
                return Application.BLOCK_OPERATIONS.setInformation(operations);
            case 7:
                Level level7 = Level.fromBytesToInformation(info);
                return Application.GET_STATE.setInformation(level7);
            case 8:
                State state = State.fromBytesToInformation(info);
                return Application.BLOCK_STATE.setInformation(state);
            case 9:
                SignedOperation signedOperation = SignedOperation.fromBytesToInformation(info);
                return Application.INJECT_OPERATION.setInformation(signedOperation);
            default:
                throw new RuntimeException("Bad Tag of Application Message");
        }
    }

    public Information getInformation(){
        return information;
    }

    @Override
    public String toString() {
        if (information == null)
            return tag + " - " + name;

        // no need to get a new line for just a number...
        if (information.getClass() == Level.class)
            return tag + " - " + name + " " + information;

        return tag + " - " + name + ": \n" + information;
    }
}
