package com.auth0;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.Validate;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Token verification utility class.
 * Supported signing algorithms: HS256 and RS256
 */
class IdTokenVerifier {

    private static final Integer DEFAULT_LEEWAY = 60; //1 min = 60 sec

    private static final String NONCE_CLAIM = "nonce";
    private static final String AZP_CLAIM = "azp";
    private static final String AUTH_TIME_CLAIM = "auth_time";

    /**
     * Verifies a provided ID Token following the OIDC specification.
     * See https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation
     *
     * @param token         the ID Token to verify.
     * @param verifyOptions the verification options, like audience, issuer, algorithm.
     * @throws TokenValidationException If the ID Token is null, its signing algorithm not supported, its signature invalid or one of its claim invalid.
     */
    void verify(String token, Options verifyOptions) throws TokenValidationException {
        Validate.notNull(verifyOptions);

        //1 presence
        if (isEmpty(token)) {
            throw new TokenValidationException("ID token is required but missing");
        }

        //2 and 3
        DecodedJWT decoded = verifyOptions.verifier.verifySignature(token);

        //4. Claims
        if (isEmpty(decoded.getIssuer())) {
            throw new TokenValidationException("Issuer (iss) claim must be a string present in the ID token");
        }
        if (!decoded.getIssuer().equals(ensureIsIssuer(verifyOptions.issuer))) {
            throw new TokenValidationException(String.format("Issuer (iss) claim mismatch in the ID token, expected \"%s\", found \"%s\"", verifyOptions.issuer, decoded.getIssuer()));
        }

        if (isEmpty(decoded.getSubject())) {
            throw new TokenValidationException("Subject (sub) claim must be a string present in the ID token");
        }

        final List<String> audience = decoded.getAudience();
        if (audience == null) {
            throw new TokenValidationException("Audience (aud) claim must be a string or array of strings present in the ID token");
        }
        if (!audience.contains(verifyOptions.audience)) {
            throw new TokenValidationException(String.format("Audience (aud) claim mismatch in the ID token; expected \"%s\" but found \"%s\"", verifyOptions.audience, decoded.getAudience()));
        }

        //epoch/seconds clock!
        final Calendar cal = Calendar.getInstance();
        final Date now = verifyOptions.clock != null ? verifyOptions.clock : cal.getTime();
        final int leeway = verifyOptions.leeway != null ? verifyOptions.leeway : DEFAULT_LEEWAY;

        if (decoded.getExpiresAt() == null) {
            throw new TokenValidationException("Expiration Time (exp) claim must be a number present in the ID token");
        }

        cal.setTime(decoded.getExpiresAt());
        cal.add(Calendar.SECOND, leeway);
        Date expDate = cal.getTime();

        if (now.after(expDate)) {
            throw new TokenValidationException(String.format("Expiration Time (exp) claim error in the ID token; current time %d is after expiration time %d", now.getTime() / 1000, expDate.getTime() / 1000));
        }

        if (decoded.getIssuedAt() == null) {
            throw new TokenValidationException("Issued At (iat) claim must be a number present in the ID token");
        }

        cal.setTime(decoded.getIssuedAt());
        cal.add(Calendar.SECOND, -1 * leeway);
        Date iatDate = cal.getTime();

        if (now.before(iatDate)) {
            throw new TokenValidationException(String.format("Issued At (iat) claim error in the ID token; current time %d is before issued at time %d", now.getTime() / 1000, iatDate.getTime() / 1000));
        }


        if (verifyOptions.nonce != null) {
            String nonceClaim = decoded.getClaim(NONCE_CLAIM).asString();
            if (isEmpty(nonceClaim)) {
                throw new TokenValidationException("Nonce (nonce) claim must be a string present in the ID token");
            }
            if (!verifyOptions.nonce.equals(nonceClaim)) {
                throw new TokenValidationException(String.format("Nonce (nonce) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.nonce, nonceClaim));
            }
        }

        if (audience.size() > 1) {
            String azpClaim = decoded.getClaim(AZP_CLAIM).asString();
            if (isEmpty(azpClaim)) {
                throw new TokenValidationException("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values");
            }
            if (!verifyOptions.audience.equals(azpClaim)) {
                throw new TokenValidationException(String.format("Authorized Party (azp) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.audience, azpClaim));
            }
        }

        if (verifyOptions.maxAge != null) {
            Date authTime = decoded.getClaim(AUTH_TIME_CLAIM).asDate();
            if (authTime == null) {
                throw new TokenValidationException("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified");
            }

            cal.setTime(authTime);
            cal.add(Calendar.SECOND, verifyOptions.maxAge);
            cal.add(Calendar.SECOND, leeway);
            Date authTimeDate = cal.getTime();

            if (now.after(authTimeDate)) {
                throw new TokenValidationException(String.format("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time %d is after last auth at %d", now.getTime() / 1000, authTimeDate.getTime() / 1000));
            }
        }
    }

    private boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private String ensureIsIssuer(String domain) {
        if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
            domain = "https://" + domain;
        }
        if (!domain.endsWith("/")) {
            domain = domain + "/";
        }
        return domain;
    }

    public static class Options {
        final String issuer;
        final String audience;
        final SignatureVerifier verifier;
        String nonce;
        private Integer maxAge;
        Integer leeway;
        Date clock;

        public Options(String issuer, String audience, SignatureVerifier verifier) {
            Validate.notNull(issuer);
            Validate.notNull(audience);
            Validate.notNull(verifier);
            this.issuer = issuer;
            this.audience = audience;
            this.verifier = verifier;
        }

        void setNonce(String nonce) {
            this.nonce = nonce;
        }

        void setMaxAge(Integer maxAge) {
            this.maxAge = maxAge;
        }

        void setLeeway(Integer leeway) {
            this.leeway = leeway;
        }

        void setClock(Date now) {
            this.clock = now;
        }

        Integer getMaxAge() {
            return maxAge;
        }
    }
}
