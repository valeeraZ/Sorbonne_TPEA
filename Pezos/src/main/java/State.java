import org.apache.commons.lang3.ArrayUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * @author Zhaojie LU
 */
public class State implements Information{
    private final byte[]  dictator_public_key;
    private final byte[] timestamp;
    private final int nbbytes;
    private final List<Account> accounts;

    public State(byte[] dictator_public_key, byte[] timestamp, int nbbytes, List<Account> accounts) {
        this.dictator_public_key = dictator_public_key;
        this.timestamp = timestamp;
        this.nbbytes = nbbytes;
        this.accounts = accounts;
    }

    public static State fromBytesToInformation(byte[] info) {
        int len = info.length;
        if (len == 0)
            throw new RuntimeException("Bad Information of State");

        byte[] dictator_public_key = ArrayUtils.subarray(info, 0, 32);
        byte[] timestamp = ArrayUtils.subarray(info, 32, 40);
        byte[] nbbytes_byte = ArrayUtils.subarray(info, 40, 44);

        int nbbytes = Utils.decodeInt(nbbytes_byte);
        int SizeAccount = 52;
        int nbAccount = nbbytes/SizeAccount;
        int init_postion_acc = 44;
        List<Account> accounts = new ArrayList<>();
        for(int i = 0; i< nbAccount; i++){
            byte[] account_byte = ArrayUtils.subarray(info, init_postion_acc,init_postion_acc+SizeAccount);
            Account account = Account.fromBytesToInformation(account_byte);
            accounts.add(account);
            init_postion_acc = init_postion_acc + SizeAccount;
        }
        return new State(dictator_public_key,timestamp,nbbytes,accounts);

    }
    @Override
    public byte[] toBytesFromInformation() {
        byte[] res;
        res = ArrayUtils.addAll(dictator_public_key);
        res = ArrayUtils.addAll(res, timestamp);
        res = ArrayUtils.addAll(res, Utils.encodeInt(nbbytes));
        for(Account a : accounts){
            res = ArrayUtils.addAll(res, a.toBytesFromInformation());
        }
        return res;
    }

    @Override
    public String toString() {
        return "State{" +
                "dictator_public_key=" + Arrays.toString(dictator_public_key) +
                ", timestamp=" + Arrays.toString(timestamp) +
                ", nbbytes=" + nbbytes +
                ", accounts=" + accounts +
                '}';
    }
}
