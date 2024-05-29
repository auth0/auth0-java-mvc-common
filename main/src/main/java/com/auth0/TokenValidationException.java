package com.auth0;

class TokenValidationException extends RuntimeException {

    TokenValidationException(String message) {
        super(message);
    }

    TokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
