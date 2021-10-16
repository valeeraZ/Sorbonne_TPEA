import java.security.*;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;

import net.i2p.crypto.eddsa.*;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 04/10/2021.
 */
public class ED25519 {

    /**
     * return a signature in byte[]
     * @param k the KeyPair of java.security
     * @param msg the message of which to sign
     * @return a signature in byte[]
     */
    public static byte[] sign(KeyPair k, byte[] msg) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sig = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sig.initSign(k.getPrivate());
        sig.update(msg);
        return sig.sign();
    }

    /**
     * verify if the signature is correct with the original message
     * @param pk the public key
     * @param msg original message
     * @param sig signature of the message
     * @return true if the signature is valid
     */
    public static boolean verify(PublicKey pk, byte [] msg, byte [] sig) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sig2 = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sig2.initVerify(pk);
        sig2.update(msg);
        return sig2.verify(sig);
    }

    /**
     * generate a Public Key from String
     * @param publicKeyStr the hex String of public key
     * @return a PublicKey
     */
    public static PublicKey generatePublicKeyFromString(String publicKeyStr){
        byte[] publicKeyByte = DatatypeConverter.parseHexBinary(publicKeyStr);
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

        EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyByte, spec);
        return new EdDSAPublicKey(publicKeySpec);
    }

    /**
     * generate a Public Key from String
     * @param privateKeyStr the hex String of public key
     * @return a PublicKey
     */
    public static PrivateKey generatePrivateKeyFromString(String privateKeyStr){
        byte[] privateKeyByte = DatatypeConverter.parseHexBinary(privateKeyStr);
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

        EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(privateKeyByte, spec);
        return new EdDSAPrivateKey(privateKeySpec);
    }

    /**
     * generate a KeyPair from String of public key and private key
     * @param publicKeyStr String of public key
     * @param privateKeyStr String of private key
     * @return a KeyPair
     */
    public static KeyPair generateKeyPairFromString(String publicKeyStr, String privateKeyStr)  {
        byte[] publicKeyByte = DatatypeConverter.parseHexBinary(publicKeyStr);
        byte[] privateKeyByte = DatatypeConverter.parseHexBinary(privateKeyStr);
        EdDSAPublicKey publicKey = null;
        EdDSAPrivateKey privateKey = null;

        try {
            KeyFactory kf = KeyFactory.getInstance("EdDSA", new EdDSASecurityProvider());
            //KeyFactorySpi keyFactory = new KeyFactory();

            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

            EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyByte, spec);
            publicKey = new EdDSAPublicKey(publicKeySpec);

            EdDSAPrivateKeySpec privateKeySpec = new EdDSAPrivateKeySpec(privateKeyByte, spec);
            privateKey = new EdDSAPrivateKey(privateKeySpec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair prepareKeyPair()  {
        return new KeyPair(generatePublicKeyFromString(Constants.PUBLIC_KEY), generatePrivateKeyFromString(Constants.PRIVATE_KEY));
    }

}
