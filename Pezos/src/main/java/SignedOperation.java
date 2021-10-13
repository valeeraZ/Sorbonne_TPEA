import org.apache.commons.lang3.ArrayUtils;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public class SignedOperation implements Information{
    private final Operation contents;
    private final byte[] publicKey;
    private final byte[] signature;

    public SignedOperation(Operation contents, byte[] publicKey, byte[] signature) {
        this.contents = contents;
        this.publicKey = publicKey;
        this.signature = signature;
    }

    @Override
    public byte[] toBytesFromInformation() {
        byte[] res;
        res = ArrayUtils.addAll(contents.toBytesOfMsg(), publicKey);
        res = ArrayUtils.addAll(res, signature);
        return res;
    }
}
