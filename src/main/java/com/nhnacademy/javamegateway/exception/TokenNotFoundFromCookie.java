package com.nhnacademy.javamegateway.exception;

public class TokenNotFoundFromCookie extends RuntimeException {

    /**
     * DEFAULT ERROR MESSAGE.
     */
    private static final String DEFAULT_ERROR = "Token not found in cookies";

    public TokenNotFoundFromCookie(String message) {
        super(message);
    }

    public TokenNotFoundFromCookie() {
        super(DEFAULT_ERROR);
    }
}
