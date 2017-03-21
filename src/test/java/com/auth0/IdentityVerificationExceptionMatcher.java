package com.auth0;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class IdentityVerificationExceptionMatcher extends TypeSafeMatcher<IdentityVerificationException> {

    public static IdentityVerificationExceptionMatcher hasCode(String code) {
        return new IdentityVerificationExceptionMatcher(code);
    }

    private String code;
    private final String expectedCode;

    private IdentityVerificationExceptionMatcher(String expectedCode) {
        this.expectedCode = expectedCode;
    }

    @Override
    protected boolean matchesSafely(IdentityVerificationException exception) {
        code = exception.getCode();
        return code.equalsIgnoreCase(expectedCode);
    }

    @Override
    public void describeTo(Description description) {
        description.appendValue(code)
                .appendText(" was not found instead of ")
                .appendValue(expectedCode);
    }

}
