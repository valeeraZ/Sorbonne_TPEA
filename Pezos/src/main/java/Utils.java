import org.apache.commons.lang3.ArrayUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Created by Wenzhuo Zhao on 11/10/2021.
 */
public class Utils {
    /**
     * encode 16bits integer to bytes
     * @param n the short (16bits integer) to convert
     * @return the byte array
     */
    public static byte[] encodeShort(short n) {
        ByteBuffer b = ByteBuffer.allocate(2);
        b.putShort(n);
        return b.array();
    }

    /**
     * decode a 16 bits integer from byte array
     * @param b the byte array
     * @return the short
     */
    public static short decodeShort(byte[] b){
        return ByteBuffer.wrap(b).getShort();
    }

    /**
     * encode 32its integer to bytes
     * @param n the int (32bits integer) to convert
     * @return the byte array
     */
    public static byte[] encodeInt(int n) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(n);
        return b.array();
    }

    /**
     * decode a 32 bits integer from byte array
     * @param b the byte array
     * @return the int
     */
    public static int decodeInt(byte[] b){
        return ByteBuffer.wrap(b).getInt();
    }

    /**
     * decode a 64 bits integer from byte array
     * @param b the byte array
     * @return the Long
     */
    public static long decodeLong(byte[] b){
        return ByteBuffer.wrap(b).getLong();
    }

    public static byte[] mergeArrays(byte[] ...arrays){
        Stream<Byte> stream = Stream.of();
        for (byte[] s: arrays) {
            stream = Stream.concat(stream, Arrays.stream(ArrayUtils.toObject(s)));
        }

        return ArrayUtils.toPrimitive(stream.toArray(Byte[]::new));
    }

    /**
     * String Hex to byte array
     * @param str the String Hex to convert
     * @return the byte array, which has a 1/2 String's length
     */
    public static byte[] hexStrToByteArray(String str)
    {
        if (str == null) {
            return null;
        }
        if (str.length() == 0) {
            return new byte[0];
        }
        byte[] byteArray = new byte[str.length() / 2];
        for (int i = 0; i < byteArray.length; i++){
            String subStr = str.substring(2 * i, 2 * i + 2);
            byteArray[i] = ((byte)Integer.parseInt(subStr, 16));
        }
        return byteArray;
    }

    /**
     * byte array to String Hex
     * @param byteArray the byte array to convert
     * @return the String array, which has a 2 times byte array's length
     */
    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
