import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 12/10/2021.
 */
@Data
public class Message {
    private final byte[] length_msg;
    private final byte[] msg;
    private Application application;

    public Message(byte[] msg){
        this.length_msg = Utils.encodeShort((short) msg.length);
        this.msg = msg;
    }

    public Message(Application app){
        this.application = app;
        this.msg = app.toBytesOfMsg();
        this.length_msg = Utils.encodeShort((short) msg.length);
    }

    public byte[] toBytesOfMsg(){
        return ArrayUtils.addAll(length_msg, msg);
    }

    public String toHexString(){
        return DatatypeConverter.printHexBinary(toBytesOfMsg());
    }

    @Override
    public String toString(){
        if (application != null)
            return application.toString();
        return DatatypeConverter.printHexBinary(msg);
    }
}
