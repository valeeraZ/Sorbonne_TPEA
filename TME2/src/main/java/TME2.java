import org.kocakosm.jblake2.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class TME2 {
    public static byte[] concat_hash(byte[] a, byte[] b) {
        byte[] hash = new byte[a.length + b.length];
        System.arraycopy(a, 0, hash, 0, a.length);
        System.arraycopy(b, 0, hash, a.length, b.length);
        Blake2b b2 = new Blake2b(32);
        b2.update(hash);
        return b2.digest();
    }

    private static ArrayList<MerkleTree> transformMerkle(ArrayList<byte[]> leaves) {
        ArrayList<MerkleTree> res = new ArrayList<MerkleTree>();
        Blake2b b2 = new Blake2b(32);
        byte[] tmp;
        for (byte[] b : leaves) {
            b2.update(b);
            tmp = b2.digest();
            b2.burn();
            res.add(new MerkleTree(tmp, null, null));
        }
        return res;
    }

    public static MerkleTree create_merkle_tree(ArrayList<byte[]> leaves) {
        ArrayList<MerkleTree> new_leaves = transformMerkle(leaves);
        ArrayList<MerkleTree> temp = new ArrayList<MerkleTree>();
        while (new_leaves.size() > 1) {

            MerkleTree gauche = new_leaves.get(0);
            MerkleTree droite = new_leaves.get(1);

            gauche.setPos(0);
            droite.setPos(1);

            byte[] tmp = concat_hash(gauche.getValue(), droite.getValue());
            MerkleTree pere = new MerkleTree(tmp, gauche, droite);
            gauche.setPere(pere);
            droite.setPere(pere);
            temp.add(pere);
            new_leaves.remove(gauche);
            new_leaves.remove(droite);

            if (new_leaves.size() == 0)
                new_leaves = temp;
        }
        return new_leaves.get(0);
    }

    public static MerkleTree witness(MerkleTree tree, MerkleTree leaf) {
        if (leaf.getPere() == null)
            return leaf;

        MerkleTree pere = leaf.getPere();

        while (pere.getPere() != null) {
            MerkleTree tmp = null;
            if (pere.getPos() == 0) {
                tmp = new MerkleTree(pere.getPere().getDroite().getValue(), null, null);
                tmp.setPere(pere.getPere());
                tmp.setPos(1);
                pere.getPere().setDroite(tmp);
            } else {
                tmp = new MerkleTree(pere.getPere().getGauche().getValue(), null, null);
                tmp.setPere(pere.getPere());
                tmp.setPos(0);
                pere.getPere().setGauche(new MerkleTree(pere.getPere().getGauche().getValue(), null, null));
            }
            pere = pere.getPere();

        }
        return pere;
    }

    private static boolean verify(byte[] a, byte[] b, byte[] tree) {
        byte[] comp = concat_hash(a, b);
        return Arrays.equals(comp, tree);
    }

    public static boolean verify(MerkleTree tree, MerkleTree witnessed) {
        if (tree.getDroite() == null && tree.getGauche() == null)
            return Arrays.equals(tree.getValue(), witnessed.getValue());

        MerkleTree gauche = tree.getGauche();
        MerkleTree droite = tree.getDroite();

        if (verify(gauche.getValue(), droite.getValue(), tree.getValue())) {
            // not contain the witnessed
            boolean okWitnessed = tree.getGauche() == null && tree.getDroite() == null&& Arrays.equals(tree.getValue(), witnessed.getValue());
            boolean nonWitnessed = tree.getGauche() == null && tree.getDroite() == null && !Arrays.equals(tree.getValue(), witnessed.getValue());

            if (okWitnessed){
                return true;
            }else {
                if(nonWitnessed){
                    return false;
                }else {
                    return verify(gauche, witnessed) || verify(droite, witnessed);
                }
            }
        } else {
            return false;
        }

    }
    
    public static String bytesToString(byte[] a){
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String[] strs = new String[]{"a", "b", "c", "d", "e", "f", "g", "h"};
        ArrayList<byte[]> leaves = new ArrayList<>();
        for (String letter : strs) {
            leaves.add(letter.getBytes());
        }
        MerkleTree tree = create_merkle_tree(leaves);
        
        MerkleTree witnessed = witness(tree, tree.getGauche().getGauche().getGauche());
        System.out.println("witnessed = " + witnessed);

        Blake2b b2 = new Blake2b(32);
        b2.update("a".getBytes());
        byte[] a = b2.digest();
        System.out.println("verify = " + verify(witnessed, new MerkleTree(a, null, null)));
    }
}
