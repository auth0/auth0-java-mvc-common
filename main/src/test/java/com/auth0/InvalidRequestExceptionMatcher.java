package com.auth0;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class InvalidRequestExceptionMatcher extends TypeSafeMatcher<InvalidRequestException> {

    private final String expectedCode;

    public static InvalidRequestExceptionMatcher hasCode(String code) {
        return new InvalidRequestExceptionMatcher(code);
    }

    private String code;

    private InvalidRequestExceptionMatcher(String expectedCode) {
        this.expectedCode = expectedCode;
    }

    @Override
    protected boolean matchesSafely(InvalidRequestException exception) {
        code = exception.getCode();

        if (expectedCode != null) {
            return expectedCode.equals(code);
        }
        return false;
    }

    @Override
    public void describeTo(Description description) {
        description.appendValue(code)
                .appendText(" was not found instead of ")
                .appendValue(expectedCode);
    }

}
