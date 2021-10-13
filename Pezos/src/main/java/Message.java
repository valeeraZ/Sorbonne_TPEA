import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 12/10/2021.
 */
public class Message {
    private final byte[] length_msg;
    private final byte[] msg;

    public Message(byte[] msg){
        this.length_msg = Utils.encodeShort((short) msg.length);
        this.msg = msg;
    }

    public Message(Application app){
        this.msg = app.toBytesOfMsg();
        this.length_msg = Utils.encodeShort((short) msg.length);
    }

    public byte[] toBytesOfMsg(){
        return ArrayUtils.addAll(length_msg, msg);
    }

    public String toHexString(){
        return DatatypeConverter.printHexBinary(toBytesOfMsg());
    }
}

enum Application {
    GET_CURRENT_HEAD((short) 1, "GET CURRENT HEAD"),
    CURRENT_HEAD((short) 2, "CURRENT HEAD"),
    GET_BLOCK((short) 3, "GET BLOCK <level>"),
    BLOCK((short) 4, "BLOCK <BLOCK>"),
    GET_BLOCK_OPERATIONS((short) 5, "GET BLOCK OPERATIONS <level>"),
    BLOCK_OPERATIONS((short) 6, "BLOCK OPERATIONS <tag> <nb bytes of OPERATIONS> <OPERATIONS>"),
    GET_STATE((short) 7, "GET STATE"),
    BLOCK_STATE((short) 8, "BLOCK STATE <STATE>"),
    INJECT_OPERATION((short) 9, "INJECT OPERATION <OPERATION>");

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
        short tag = Utils.decodeShort(ArrayUtils.subarray(app, 0, 2));
        byte[] info = ArrayUtils.subarray(app, 2, app.length);
        switch (tag){
            case 1:
                return Application.GET_CURRENT_HEAD;
            case 2:
                Block b2 = Block.fromBytesToInformation(info);
                return Application.CURRENT_HEAD.setInformation(b2);
            case 4:
                Block b4 = Block.fromBytesToInformation(info);
                return Application.BLOCK.setInformation(b4);
            default:
                return Application.GET_CURRENT_HEAD;
        }
    }

    @Override
    public String toString() {
        if (information == null)
            return tag + " - " + name;
        return tag + " - " + name + " content: \n" + information;
    }
}
