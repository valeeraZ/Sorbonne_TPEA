import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
@Data
public class SignedOperations implements Information {
    private final List<SignedOperation> signedOperations;

    public SignedOperations(List<SignedOperation> signedOperations) {
        this.signedOperations = signedOperations;
    }

    public static SignedOperations fromBytesToInformation(byte[] seqOps)  {
        List<SignedOperation> signedOps = new ArrayList<>();
        int lengthSignedOp = 0;
        boolean end = false;
        while (!end && seqOps.length > 0) {
            short tag = Utils.decodeShort(ArrayUtils.subarray(seqOps, 0, Constants.TAG_SIZE));
            switch (tag) {
                case 1:
                case 3:
                case 4:
                    lengthSignedOp = Constants.TAG_SIZE + Constants.HASH_SIZE + Constants.PUBLIC_KEY_SIZE + Constants.SIGNATURE_SIZE;
                    byte[] info = ArrayUtils.subarray(seqOps, 0, lengthSignedOp);
                    SignedOperation signedOp = SignedOperation.fromBytesToInformation(info);
                    seqOps = ArrayUtils.subarray(seqOps, lengthSignedOp, seqOps.length);
                    signedOps.add(signedOp);
                    break;
                case 2:
                    lengthSignedOp = Constants.TAG_SIZE + Constants.TIMESTAMP_SIZE + Constants.PUBLIC_KEY_SIZE + Constants.SIGNATURE_SIZE;
                    byte[] info2 = ArrayUtils.subarray(seqOps, 0, lengthSignedOp);
                    SignedOperation signedOp2 = SignedOperation.fromBytesToInformation(info2);
                    seqOps = ArrayUtils.subarray(seqOps, lengthSignedOp, seqOps.length);
                    signedOps.add(signedOp2);
                    break;
                case 5:
                    lengthSignedOp = Constants.TAG_SIZE + Constants.PUBLIC_KEY_SIZE + Constants.SIGNATURE_SIZE;
                    byte[] info5 = ArrayUtils.subarray(seqOps, 0, lengthSignedOp);
                    SignedOperation signedOp5 = SignedOperation.fromBytesToInformation(info5);
                    seqOps = ArrayUtils.subarray(seqOps, lengthSignedOp, seqOps.length);
                    signedOps.add(signedOp5);
                    break;
                default:
                    end = true;
            }
        }
        return new SignedOperations(signedOps);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        signedOperations.forEach(sop -> sb.append(sop).append("\n"));
        return sb.toString();
    }

    @Override
    public byte[] toBytesFromInformation() {
        byte[] res = new byte[0];
        for (SignedOperation signedOp : signedOperations) {
            res = ArrayUtils.addAll(res, signedOp.toBytesFromInformation());
        }
        return res;
    }
}
