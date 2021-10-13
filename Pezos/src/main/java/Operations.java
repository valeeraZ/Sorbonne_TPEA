import java.util.ArrayList;
import java.util.List;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public class Operations implements Information{
    private final List<Operation> operations;

    public Operations(List<Operation> operations) {
        this.operations = operations;
    }

    public static Operations fromBytesToInformation(byte[] seqOps){
        //TODO
        return new Operations(new ArrayList<>());
    }

    @Override
    public byte[] toBytesFromInformation() {
        //TODO
        return new byte[0];
    }
}
