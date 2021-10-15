import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.commons.lang3.ArrayUtils;
import org.kocakosm.jblake2.Blake2b;

import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
@Data
@Slf4j
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

    public static SignedOperation fromBytesToInformation(byte[] info)  {
        int len = info.length;
        int offset_signature = len - Constants.SIGNATURE_SIZE;
        int offset_publicKey = offset_signature - Constants.PUBLIC_KEY_SIZE;
        byte[] signature = ArrayUtils.subarray(info, offset_signature, len);
        byte[] publicKeyByte = ArrayUtils.subarray(info, offset_publicKey, offset_signature);
        byte[] contentsByte = ArrayUtils.subarray(info, 0, offset_publicKey);

        // verify the signature of operation
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyByte, spec);
        PublicKey publicKey = new EdDSAPublicKey(publicKeySpec);
        byte[] concatBytes = ArrayUtils.addAll(contentsByte, publicKeyByte);
        Blake2b b2 = new Blake2b(32);
        b2.update(concatBytes);
        byte[] hash = b2.digest();
        try {
            assert ED25519.verify(publicKey, hash, signature);
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e){
            log.warn("Bad Ed25519 Algorithme or Bad Signature");
        }

        Operation contents = Operation.fromBytesToInformation(contentsByte);
        return new SignedOperation(contents, publicKeyByte, signature);
    }

    @Override
    public String toString() {
        return contents.toString();
    }
}
