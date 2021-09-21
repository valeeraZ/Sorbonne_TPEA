import org.kocakosm.jblake2.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public class BlockChains {

    // Ex1 Q1
    public static byte[] hash_id(String name, String firstname){
        String str = name + ":" + firstname;
        Blake2b b2 = new Blake2b(32);
        byte[] byteArr = str.getBytes();
        b2.update(byteArr);
        return b2.digest();
    }


    // encode 32bits integer to binary
    private static byte[] encode(int n) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(n);
        return b.array();
    }

    // Ex1 Q2
    public static byte[] hash_value(byte[] hashId, int nonce) throws NoSuchAlgorithmException, IOException {
        byte[] number_encoded = encode(nonce);

        Blake2b b2 = new Blake2b(32);
        b2.update(hashId);
        b2.update(number_encoded);
        return b2.digest();
    }

    // Ex2 Q1
    public static int count_zero_prefix(String s) {
        int res = 0;
        for (char c : s.toCharArray()) {
            if (c == '0')
                res++;
            else
                break;
        }
        return res;
    }

    // Ex2 Q2
    public static boolean is_valid(String nom, String prenom, int nonce, int n)
            throws NoSuchAlgorithmException, IOException {
        byte[] value = hash_value(hash_id(nom, prenom), nonce);
        StringBuilder sb = new StringBuilder();
        for (byte b1 : value) {
            //if width < 8 then give padding of ' '
            //replace the padding ' ' by 0
            sb.append(String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0'));
        }
        int nb = count_zero_prefix(sb.toString());
        return nb >= n;
    }

    // Ex2 Q3
    public static int mine(String name, String firstname, int n) throws NoSuchAlgorithmException, IOException {
        int nonce = 0;
        while (!is_valid(name, firstname, nonce, n)) {
            nonce++;
        }
        return nonce;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        //Ex1 Q1
        byte[] hashId = hash_id("nakamoto", "satoshi");
        StringBuilder sb = new StringBuilder();
        for (byte b : hashId) {
            sb.append(String.format("%02x", b));
        }
        System.out.println("Test hash_id for nakamoto:satoshi = " + sb.toString());

        //Ex1 Q2
        byte[] hashValue = hash_value(hashId, 123);
        StringBuilder sb2 = new StringBuilder();
        for (byte b : hashValue) {
            sb2.append(String.format("%02x", b));
        }
        System.out.println("Test hash_value for nakamoto:satoshi and 123 = " + sb2.toString());

        //Ex2 Q2
        System.out.println("Test mine = "+mine("nakamoto", "satoshi", 15));
    }
    
}
