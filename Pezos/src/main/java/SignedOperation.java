import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.commons.lang3.ArrayUtils;
import org.kocakosm.jblake2.Blake2b;

import java.security.*;

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

    /**
     * sign an operation to be injected using our key
     * @param contents an operation to be injected
     */
    public SignedOperation(Operation contents){
        this.contents = contents;
        this.publicKey = Constants.PUBLIC_KEY_BYTES;

        byte[] concatBytes = ArrayUtils.addAll(contents.toBytesFromOperation(), publicKey);
        Blake2b b2 = new Blake2b(32);
        b2.update(concatBytes);
        byte[] hash = b2.digest();

        KeyPair keyPair = ED25519.prepareKeyPair();
        try {
            this.signature = ED25519.sign(keyPair, hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e.getMessage());
        }

    }

    @Override
    public byte[] toBytesFromInformation() {
        return Utils.mergeArrays(contents.toBytesFromOperation(), publicKey, signature);
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
