import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

/**
 * @author Zhaojie LU
 */
public class Account implements Information {
//            user public key | 32 bytes | bytes |
//            +---------------------+----------+----------------+
//            | level pez | 4 bytes | 32-bit integer |
//            +---------------------+----------+----------------+
//            | timestamp pez | 4 bytes | 32-bit integer |
//            +---------------------+----------+----------------+
//            | operations_hash pez | 4 bytes | 32-bit integer |
//            +---------------------+----------+----------------+
//            | context_hash pez | 4 bytes | 32-bit integer |
//            +---------------------+----------+----------------+
//            | signature pez | 4 bytes | 32-bit integer

    private final byte[] user_public_key;
    private final int predecessor_pez;
    private final int timestamp_pez;
    private final int operations_hash_pez;
    private final int context_hash_pez;
    private final int signature_pez;


    public Account(byte[] user_public_key, int level_pez, int timestamp_pez, int operations_hash_pez, int context_hash_pez, int signature_pez) {
        this.user_public_key = user_public_key;
        this.predecessor_pez = level_pez;
        this.timestamp_pez = timestamp_pez;
        this.operations_hash_pez = operations_hash_pez;
        this.context_hash_pez = context_hash_pez;
        this.signature_pez = signature_pez;
    }

    public static Account fromBytesToInformation(byte[] info) {
        int len = info.length;
        if (len != 52)
            throw new RuntimeException("Bad Information of Account");

        byte[] user_public_key = ArrayUtils.subarray(info, 0, 32);
        int predecessor_pez = Utils.decodeInt(ArrayUtils.subarray(info, 32, 36));
        int timestamp_pez = Utils.decodeInt(ArrayUtils.subarray(info, 36, 40));
        int operations_hash_pez = Utils.decodeInt(ArrayUtils.subarray(info, 40, 44));
        int context_hash_pez = Utils.decodeInt(ArrayUtils.subarray(info, 44, 48));
        int signature_pez = Utils.decodeInt(ArrayUtils.subarray(info, 48, 52));
        return new Account(user_public_key, predecessor_pez, timestamp_pez, operations_hash_pez, context_hash_pez, signature_pez);
    }

    @Override
    public byte[] toBytesFromInformation() {
        byte[] res;
        res = ArrayUtils.addAll(user_public_key);
        res = ArrayUtils.addAll(res, Utils.encodeInt(predecessor_pez));
        res = ArrayUtils.addAll(res, Utils.encodeInt(timestamp_pez));
        res = ArrayUtils.addAll(res, Utils.encodeInt(operations_hash_pez));
        res = ArrayUtils.addAll(res, Utils.encodeInt(context_hash_pez));
        res = ArrayUtils.addAll(res, Utils.encodeInt(signature_pez));
        return res;
    }

    public boolean getMyAccount(){
        return Arrays.equals(this.user_public_key, Constants.PUBLIC_KEY_BYTES);
    }

    @Override
    public String toString() {
        return "user_public_key: " + DatatypeConverter.printHexBinary(user_public_key) + "\n" +
                "predecessor_pez: " + predecessor_pez + "\n" +
                "timestamp_pez: " + timestamp_pez + "\n" +
                "operations_hash_pez: " + operations_hash_pez + "\n" +
                "context_hash_pez: " + context_hash_pez + "\n" +
                "signature_pez: " + signature_pez;
    }
}
