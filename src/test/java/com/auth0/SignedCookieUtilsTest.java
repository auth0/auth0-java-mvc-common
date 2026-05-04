package com.auth0;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignedCookieUtilsTest {

    private static final String SECRET = "testClientSecret123";
    private static final String DOMAIN = "tenant-a.auth0.com";

    // --- sign() tests ---

    @Test
    public void shouldSignValue() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);

        assertThat(signed, is(notNullValue()));
        assertThat(signed, containsString(DOMAIN));
        assertThat(signed, containsString("|"));

        // Should have format: value|hex-signature
        String[] parts = signed.split("\\|");
        assertThat(parts.length, is(2));
        assertThat(parts[0], is(DOMAIN));
        // HMAC-SHA256 hex is 64 characters
        assertThat(parts[1].length(), is(64));
    }

    @Test
    public void shouldProduceDeterministicSignature() {
        String signed1 = SignedCookieUtils.sign(DOMAIN, SECRET);
        String signed2 = SignedCookieUtils.sign(DOMAIN, SECRET);

        assertThat(signed1, is(signed2));
    }

    @Test
    public void shouldProduceDifferentSignaturesForDifferentValues() {
        String signed1 = SignedCookieUtils.sign("domain-a.auth0.com", SECRET);
        String signed2 = SignedCookieUtils.sign("domain-b.auth0.com", SECRET);

        assertThat(signed1, is(not(signed2)));
    }

    @Test
    public void shouldProduceDifferentSignaturesForDifferentSecrets() {
        String signed1 = SignedCookieUtils.sign(DOMAIN, "secret-1");
        String signed2 = SignedCookieUtils.sign(DOMAIN, "secret-2");

        assertThat(signed1, is(not(signed2)));
    }

    @Test
    public void shouldThrowWhenSigningNullValue() {
        assertThrows(IllegalArgumentException.class, () ->
                SignedCookieUtils.sign(null, SECRET));
    }

    @Test
    public void shouldThrowWhenSigningWithNullSecret() {
        assertThrows(IllegalArgumentException.class, () ->
                SignedCookieUtils.sign(DOMAIN, null));
    }

    // --- verifyAndExtract() tests ---

    @Test
    public void shouldVerifyAndExtractValidSignature() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);

        String extracted = SignedCookieUtils.verifyAndExtract(signed, SECRET);

        assertThat(extracted, is(DOMAIN));
    }

    @Test
    public void shouldRejectTamperedValue() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);
        // Tamper with the domain portion
        String tampered = "evil.attacker.com" + signed.substring(signed.indexOf("|"));

        String extracted = SignedCookieUtils.verifyAndExtract(tampered, SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldRejectTamperedSignature() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);
        // Tamper by flipping the last hex character
        char lastChar = signed.charAt(signed.length() - 1);
        char flipped = (lastChar == 'a') ? 'b' : 'a';
        String tampered = signed.substring(0, signed.length() - 1) + flipped;

        String extracted = SignedCookieUtils.verifyAndExtract(tampered, SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldRejectWrongSecret() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);

        String extracted = SignedCookieUtils.verifyAndExtract(signed, "wrong-secret");

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForNullSignedValue() {
        String extracted = SignedCookieUtils.verifyAndExtract(null, SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForNullSecret() {
        String signed = SignedCookieUtils.sign(DOMAIN, SECRET);

        String extracted = SignedCookieUtils.verifyAndExtract(signed, null);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForMissingSeparator() {
        String extracted = SignedCookieUtils.verifyAndExtract("noseparatorhere", SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForEmptyValue() {
        String extracted = SignedCookieUtils.verifyAndExtract("|signature", SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForEmptySignature() {
        String extracted = SignedCookieUtils.verifyAndExtract("value|", SECRET);

        assertThat(extracted, is(nullValue()));
    }

    @Test
    public void shouldHandleDomainWithSpecialCharacters() {
        String domain = "my-custom-domain.example.co.uk";
        String signed = SignedCookieUtils.sign(domain, SECRET);
        String extracted = SignedCookieUtils.verifyAndExtract(signed, SECRET);

        assertThat(extracted, is(domain));
    }

    @Test
    public void shouldRejectCompletelyFabricatedValue() {
        // Attacker creates their own domain + fake signature
        String fabricated = "evil.auth0.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        String extracted = SignedCookieUtils.verifyAndExtract(fabricated, SECRET);

        assertThat(extracted, is(nullValue()));
    }
}
