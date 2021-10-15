import javax.xml.bind.DatatypeConverter;

/**
 * Created by Wenzhuo Zhao on 11/10/2021.
 */
public class Constants {
    static final String PUBLIC_KEY = "bfb86ca90eb0d4b6818aff69c60261c87f67406ff90505bd7b8be60d4194c11c";

    static final byte[] PUBLIC_KEY_BYTES = DatatypeConverter.parseHexBinary(PUBLIC_KEY);

    static final String PRIVATE_KEY = "d8c6cedcebb0e4766f773eee2284f70ae79571824baa8bc3a4b869d1d54ea64b";

    static final String IP = "78.194.168.67";

    static final String PORT = "1337";

    static final int TAG_SIZE = 2;

    static final int BLOCK_SIZE = 172;

    static final int PUBLIC_KEY_SIZE = 32;

    static final int TIMESTAMP_SIZE = 8;

    static final int HASH_SIZE = 32;

    static final int SIGNATURE_SIZE = 64;

    // a sequence of all 5 signed operations has 594 bytes
    static final int MAX_SIGNED_OPS_SIZE = 594;
}
