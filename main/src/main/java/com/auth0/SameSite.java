package com.auth0;

/**
 * Represents the values for the SameSite cookie attribute.
 *
 * @see <a href="https://www.owasp.org/index.php/SameSite">OWASP - SameSite</a> for additional information about the SameSite attribute..
 */
enum SameSite {
    LAX("Lax"),
    NONE("None"),
    STRICT("Strict");

    private String value;

    String getValue() {
        return this.value;
    }

    SameSite(String value) {
        this.value = value;
    }
}