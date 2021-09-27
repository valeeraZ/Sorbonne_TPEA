
public class MerkleTree {
    private byte[] value;
    private MerkleTree gauche, droite, pere;
    private int pos;

    public MerkleTree(byte[] value, MerkleTree g, MerkleTree d) {
        this.value = value;
        gauche = g;
        droite = d;
        pere = null;
    }

    public MerkleTree() {
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }

    public MerkleTree getGauche() {
        return gauche;
    }

    public void setGauche(MerkleTree gauche) {
        this.gauche = gauche;
    }

    public MerkleTree getDroite() {
        return droite;
    }

    public void setDroite(MerkleTree droite) {
        this.droite = droite;
    }

    public MerkleTree getPere() {
        return pere;
    }

    public void setPere(MerkleTree pere) {
        this.pere = pere;
    }

    @Override
    public String toString() {
        return "MerkleTree [gauche = " + gauche + ", droite = " + droite + " value = " + TME2.bytesToString(value) +"]";
    }

    public int getPos() {
        return pos;
    }

    public void setPos(int pos) {
        this.pos = pos;
    }
}
