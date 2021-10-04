import java.io.*;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 04/10/2021.
 */
public class ED25519 {

    final KeyPairGenerator gen;

    public ED25519() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new EdDSASecurityProvider());
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        gen = KeyPairGenerator.getInstance("EdDSA", "EdDSA");
        sr.setSeed(System.currentTimeMillis());
        gen.initialize(256,sr);
    }

    public KeyPair generateKeys() {
        return gen.generateKeyPair();
    }

    public static byte[] sign(KeyPair k, byte[] msg) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sig = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sig.initSign(k.getPrivate());
        sig.update(msg);
        return sig.sign();
    }

    public static boolean verify(PublicKey pk, byte [] msg, byte [] sig) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sig2 = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sig2.initVerify(pk);
        sig2.update(msg);
        return sig2.verify(sig);
    }

    public static void verifyFile(String fileName){
        File file = new File(fileName);
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String publicKeyStr, signatureStr, dataStr;

            int i = 0;
            int index = 1;
            while ((publicKeyStr = reader.readLine()) != null) {
                signatureStr = reader.readLine();
                dataStr = reader.readLine();
                // read a white line
                reader.readLine();

                byte[] publicKeyByte = DatatypeConverter.parseHexBinary(publicKeyStr);
                byte[] signatureByte = DatatypeConverter.parseHexBinary(signatureStr);
                byte[] dataByte = DatatypeConverter.parseHexBinary(dataStr);

                KeyFactory kf = KeyFactory.getInstance("EdDSA");
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
                EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKeyByte, spec);
                PublicKey publicKey = kf.generatePublic(publicKeySpec);
                if(!verify(publicKey, dataByte, signatureByte)){
                    System.out.println("indice de données incorrectes: " + index);
                    i++;
                }
                index++;
            }
            System.out.println("Nombre de données incorrectes: " + i);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        ED25519 ed25519 = new ED25519();
        KeyPair keyPair = ed25519.generateKeys();
        byte[] signature = sign(keyPair, "datatest".getBytes());
        System.out.println("Original data test: " + verify(keyPair.getPublic(), "datatest".getBytes(), signature));
        System.out.println("Bad data test: " + verify(keyPair.getPublic(), "baddatatest".getBytes(), signature));

        verifyFile("tme3_data");

    }

}
