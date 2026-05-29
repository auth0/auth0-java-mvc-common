package com.auth0;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for HMAC-signing cookie values to prevent tampering.
 * <p>
 * Values are stored as {@code value|signature} where the signature is an
 * HMAC-SHA256 hex digest computed using the application's client secret.
 * On read, the signature is verified before the value is trusted.
 */
class SignedCookieUtils {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SEPARATOR = "|";

    private SignedCookieUtils() {}

    /**
     * Signs a value using HMAC-SHA256 with the provided secret.
     *
     * @param value  the value to sign
     * @param secret the secret key for HMAC
     * @return the signed value in the format {@code value|signature}
     * @throws IllegalArgumentException if value or secret is null
     */
    static String sign(String value, String secret) {
        if (value == null || secret == null) {
            throw new IllegalArgumentException("Value and secret must not be null");
        }
        String signature = computeHmac(value, secret);
        return value + SEPARATOR + signature;
    }

    /**
     * Signs a value using HMAC-SHA256 with the provided secret, binding it to a
     * context value (e.g., state). The context is included in the HMAC computation
     * but not stored in the cookie — the verifier must supply the same context.
     *
     * @param value   the value to sign and store
     * @param context the binding context (e.g., state parameter) included in HMAC
     * @param secret  the secret key for HMAC
     * @return the signed value in the format {@code value|signature}
     * @throws IllegalArgumentException if any argument is null
     */
    static String sign(String value, String context, String secret) {
        if (value == null || context == null || secret == null) {
            throw new IllegalArgumentException("Value, context, and secret must not be null");
        }
        String signature = computeHmac(value + SEPARATOR + context, secret);
        return value + SEPARATOR + signature;
    }

    /**
     * Verifies the HMAC signature and extracts the original value.
     *
     * @param signedValue the signed value in the format {@code value|signature}
     * @param secret      the secret key used to verify the HMAC
     * @return the original value if the signature is valid, or {@code null} if
     *         the signature is invalid or the format is unexpected
     */
    static String verifyAndExtract(String signedValue, String secret) {
        if (signedValue == null || secret == null) {
            return null;
        }

        int separatorIndex = signedValue.lastIndexOf(SEPARATOR);
        if (separatorIndex <= 0 || separatorIndex >= signedValue.length() - 1) {
            return null;
        }

        String value = signedValue.substring(0, separatorIndex);
        String signature = signedValue.substring(separatorIndex + 1);

        String expectedSignature = computeHmac(value, secret);

        // Constant-time comparison to prevent timing attacks
        if (MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            return value;
        }

        return null;
    }

    /**
     * Verifies the HMAC signature (which was computed with a binding context) and
     * extracts the original value.
     *
     * @param signedValue the signed value in the format {@code value|signature}
     * @param context     the binding context that was used during signing
     * @param secret      the secret key used to verify the HMAC
     * @return the original value if the signature is valid, or {@code null} if
     *         the signature is invalid, the context doesn't match, or the format
     *         is unexpected
     */
    static String verifyAndExtract(String signedValue, String context, String secret) {
        if (signedValue == null || context == null || secret == null) {
            return null;
        }

        int separatorIndex = signedValue.lastIndexOf(SEPARATOR);
        if (separatorIndex <= 0 || separatorIndex >= signedValue.length() - 1) {
            return null;
        }

        String value = signedValue.substring(0, separatorIndex);
        String signature = signedValue.substring(separatorIndex + 1);

        String expectedSignature = computeHmac(value + SEPARATOR + context, secret);

        // Constant-time comparison to prevent timing attacks
        if (MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            return value;
        }

        return null;
    }

    private static String computeHmac(String value, String secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to compute HMAC-SHA256", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
