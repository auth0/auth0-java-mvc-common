package com.auth0;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class InvalidRequestExceptionMatcher extends TypeSafeMatcher<InvalidRequestException> {

    private final String expectedDescription;
    private final String expectedCode;

    public static InvalidRequestExceptionMatcher hasCode(String code) {
        return new InvalidRequestExceptionMatcher(code, null);
    }

    public static InvalidRequestExceptionMatcher hasDescription(String description) {
        return new InvalidRequestExceptionMatcher(null, description);
    }

    private String description;
    private String code;

    private InvalidRequestExceptionMatcher(String expectedCode, String expectedDescription) {
        this.expectedCode = expectedCode;
        this.expectedDescription = expectedDescription;
    }

    @Override
    protected boolean matchesSafely(InvalidRequestException exception) {
        code = exception.getCode();
        description = exception.getDescription();

        if (expectedDescription != null) {
            return expectedDescription.equals(description);
        }
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
