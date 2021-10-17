import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

import javax.xml.bind.DatatypeConverter;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * @author Zhaojie LU
 */
@Data
public class State implements Information{
    private final byte[]  dictator_public_key;
    private final byte[] timestamp;
    private final int nbbytes;
    private final List<Account> accounts;

    public byte[] getDictator_public_key() {
        return dictator_public_key;
    }

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
        StringBuilder sb = new StringBuilder();
        sb.append("dictator_public_key: ").append(DatatypeConverter.printHexBinary(dictator_public_key)).append("\n");
        sb.append("timestamp: ").append(new Timestamp(Utils.decodeLong(timestamp) * 1000)).append("\n");
        sb.append("byte size of accounts: ").append(nbbytes).append("\n");
        sb.append("accounts:").append("\n");
        for (Account account : accounts){
            sb.append(account.toString()).append("\n");
            sb.append("----------------------------").append("\n");
        }
        return sb.toString();
    }
}
