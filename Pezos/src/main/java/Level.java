/**
 * Created by Wenzhuo Zhao on 13/10/2021.
 */
public class Level implements Information{
    private final int level;

    public Level(int level) {
        this.level = level;
    }

    public static Level fromBytesToInformation(byte[] info){
        return new Level(Utils.decodeInt(info));
    }

    @Override
    public byte[] toBytesFromInformation() {
        return Utils.encodeInt(level);
    }

    @Override
    public String toString() {
        return String.valueOf(level);
    }
}
