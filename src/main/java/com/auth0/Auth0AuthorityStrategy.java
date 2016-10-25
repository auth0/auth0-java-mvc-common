package com.auth0;

/**
 * The authority strategy being used - can be either ROLES, GROUPS, or SCOPE
 *
 * For API Resource Server using JWT Access Tokens - `scope` is the default.
 * This is a claim added to the JWT Access token whose values are the scope
 * values representing the permissions granted.
 *
 * For MVC applications, custom RULES may apply ROLES or GROUPS claim on the ID Token
 * whose values are the scope values representing the permissions granted.
 */
public enum Auth0AuthorityStrategy {

    GROUPS("groups"),
    ROLES("roles"),
    SCOPE("scope");

    private final String name;

    /**
     * @param name the name of the authority strategy
     */
    Auth0AuthorityStrategy(final String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    /**
     * Indicates whether this Authority Strategy contains the value supplied
     * @param value the value to check
     * @return boolean indicating whether found
     */
    public static boolean contains(final String value) {
        for (final Auth0AuthorityStrategy authorityStrategy : Auth0AuthorityStrategy.values()) {
            if (authorityStrategy.name().equals(value)) {
                return true;
            }
        }
        return false;
    }

}
