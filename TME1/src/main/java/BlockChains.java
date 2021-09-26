import org.kocakosm.jblake2.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

public class BlockChains {

    // Ex1 Q1
    public static byte[] hash_id(String name, String firstname){
        String str = name + ":" + firstname;
        Blake2b b2 = new Blake2b(32);
        byte[] byteArr = str.getBytes();
        b2.update(byteArr);
        return b2.digest();
    }


    // encode 32bits integer to bytes
    private static byte[] encode(int n) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(n);
        return b.array();
    }

    // Ex1 Q2
    public static byte[] hash_value(byte[] hashId, int nonce)  {
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
    public static boolean is_valid(String name, String firstname, int nonce, int n) {
        byte[] value = hash_value(hash_id(name, firstname), nonce);
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
    public static int mine(String name, String firstname, int n) {
        int nonce = 0;
        while (!is_valid(name, firstname, nonce, n)) {
            nonce++;
        }
        return nonce;
    }


    static class Compte{
        String hashId;
        int amount;

        public Compte(String hashId, int amount) {
            this.hashId = hashId;
            this.amount = amount;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Compte compte = (Compte) o;
            return amount == compte.amount && hashId.equals(compte.hashId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hashId, amount);
        }

        @Override
        public String toString() {
            return "(" + hashId + ", " + amount + ")";
        }
    }

    // Ex3 Q1
    // hash_id: char -> ascii, montant: int -> hex
    public static byte[] encode_compte(Compte compte) throws IOException {
        byte[] encoded_ascii = compte.hashId.getBytes(StandardCharsets.US_ASCII);
        byte[] encoded_amount = encode(compte.amount);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encoded_ascii);
        outputStream.write(encoded_amount);

        return outputStream.toByteArray();
    }

    public static Compte decode_compte(byte[] encoded_compte){
        byte[] encoded_hashId = new byte[64];
        byte[] encoded_amount = new byte[4];

        System.arraycopy(encoded_compte, 0, encoded_hashId, 0, 64);
        System.arraycopy(encoded_compte, 64, encoded_amount, 0, 4);

        String hashId = new String(encoded_hashId, StandardCharsets.US_ASCII);
        int amount = ByteBuffer.wrap(encoded_amount).getInt();

        return new Compte(hashId, amount);
    }

    // Ex3 Q2
    // get length of Array to have a prefix and use encode(int) to encode it
    public static byte[] encode_etat(ArrayList<Compte> comptes) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int nb_comptes = comptes.size();
        byte[] prefix = encode(nb_comptes);
        outputStream.write(prefix);

        for (Compte c: comptes) {
            byte[] encoded_compte = encode_compte(c);
            outputStream.write(encoded_compte);
        }

        return outputStream.toByteArray();
    }

    // Ex3 Q2
    public static ArrayList<Compte> decode_etat(byte[] encoded_etat){
        byte[] encoded_size = new byte[4];
        System.arraycopy(encoded_etat, 0, encoded_size, 0, 4);
        int size = ByteBuffer.wrap(encoded_size).getInt();

        ArrayList<Compte> etat = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            byte[] encoded_compte = new byte[68];//64 hashId + 4 amount
            System.arraycopy(encoded_etat, 4+(68*i), encoded_compte, 0, 68);
            Compte c = decode_compte(encoded_compte);
            etat.add(c);
        }

        return etat;
    }

    public static void main(String[] args) throws IOException {
        //Ex1 Q1
        byte[] hashId = hash_id("nakamoto", "satoshi");
        StringBuilder sb = new StringBuilder();
        for (byte b : hashId) {
            sb.append(String.format("%02x", b));
        }
        System.out.println("Test hash_id for nakamoto:satoshi = " + sb.toString());
        System.out.println();

        //Ex1 Q2
        byte[] hashValue = hash_value(hashId, 123);
        StringBuilder sb2 = new StringBuilder();
        for (byte b : hashValue) {
            sb2.append(String.format("%02x", b));
        }
        System.out.println("Test hash_value for tuple (nakamoto:satoshi, 123) = " + sb2.toString());
        System.out.println();

        //Ex2 Q2
        System.out.println("Test mine = "+mine("nakamoto", "satoshi", 15));
        System.out.println();

        //Ex3 Q1
        String test_hashId = "1dc653a1447946592fe2871eeb01d8fd6ae353bf04ab789199e38777da3fd0c7";
        Compte compte = new Compte(test_hashId, 1003);
        byte[] encoded_compte = encode_compte(compte);

        StringBuilder sb3 = new StringBuilder();
        for (byte b : encoded_compte) {
            sb3.append(String.format("%02x", b));
        }
        System.out.println("Test encoded compte = " + sb3.toString());

        Compte new_compte = decode_compte(encoded_compte);
        System.out.println("Test decoded compte = " + new_compte.toString());
        System.out.println("Test compte equals decoded compte = " + compte.equals(new_compte));
        System.out.println();

        //Ex3 Q2
        Compte c1 = new Compte("1dc653a1447946592fe2871eeb01d8fd6ae353bf04ab789199e38777da3fd0c7", 1003);
        Compte c2 = new Compte("ad415c298389574a24f009671697dd58a717ec04aaa79bd39a130b1ae7a4b2a9", 8532);
        Compte c3 = new Compte("b6a46ab620ab41132a7e062bee0bd7ef6af99d5c25b9021edcb949f2cd6c2bbc", 100);
        Compte c4 = new Compte("d91340a0a4fc7283117fb7871a95e983455275347662345ffaaa75d674def6ec", 943);
        Compte c5 = new Compte("ff9f179535d17c8f29d7eb8ad3432eb8b16ce684b48527b12a1a71f10d3e63ec", 755);
        ArrayList<Compte> comptes = new ArrayList<>(Arrays.asList(c1, c2, c3, c4, c5));

        byte[] encoded_etat = encode_etat(comptes);
        StringBuilder sb4 = new StringBuilder();
        for (byte b : encoded_etat) {
            sb4.append(String.format("%02x", b));
        }
        System.out.println("Test encoded etat = \n" + sb4.toString());

        ArrayList<Compte> decoded_etat = decode_etat(encoded_etat);
        System.out.println("Test decoded etat = " + decoded_etat);

        System.out.println("Test etat equals decoded etat = " + comptes.equals(decoded_etat));

    }
}