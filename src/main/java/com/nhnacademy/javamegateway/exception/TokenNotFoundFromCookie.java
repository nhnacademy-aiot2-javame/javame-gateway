package com.nhnacademy.javamegateway.exception;

import org.springframework.http.HttpStatus;

public class TokenNotFoundFromCookie extends RuntimeException {

    /**
     * DEFAULT ERROR MESSAGE.
     */
    private static final String DEFAULT_ERROR = "Token not found in cookies";

    /**
     * TokenNotFoundFromCookie 쿠키에서 토큰을 찾지 못했을 때 발생하는 예외입니다.
     * HttpStatus = 400.
     */
    private static final HttpStatus status = HttpStatus.BAD_REQUEST;

    public TokenNotFoundFromCookie(String message) {
        super(message);
    }

    public TokenNotFoundFromCookie() {
        super(DEFAULT_ERROR);
    }
}
