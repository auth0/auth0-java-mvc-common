package com.auth0;

import java.util.Random;

/**
 * Create a randomly generated Nonce value (for example: D27906B34E8B08554F43E0CDC4904BB2)
 * that can be stored in State param to correlate requests with callbacks and ensure validity.
 */
public class NonceFactory {

    private static final Random randomSource = new Random();

    /**
     * Create a randomly generated Nonce value (for example: D27906B34E8B08554F43E0CDC4904BB2)
     * @return the nonce value
     */
    public static String create() {
        byte random[] = new byte[16];
        StringBuilder buffer = new StringBuilder();
        randomSource.nextBytes(random);
        for (int j = 0; j < random.length; j++) {
            byte b1 = (byte) ((random[j] & 0xf0) >> 4);
            byte b2 = (byte) (random[j] & 0x0f);
            if (b1 < 10)
                buffer.append((char) ('0' + b1));
            else
                buffer.append((char) ('A' + (b1 - 10)));
            if (b2 < 10)
                buffer.append((char) ('0' + b2));
            else
                buffer.append((char) ('A' + (b2 - 10)));
        }
        return buffer.toString();
    }

}
