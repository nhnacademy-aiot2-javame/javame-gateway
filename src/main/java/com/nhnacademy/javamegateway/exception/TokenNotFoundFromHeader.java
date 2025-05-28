package com.nhnacademy.javamegateway.exception;

import org.springframework.http.HttpStatus;

public class TokenNotFoundFromHeader extends RuntimeException {

    /**
     * DEFAULT ERROR MESSAGE.
     */
    private static final String DEFAULT_ERROR = "Token not found in authorization header";

    /**
     * TokenNotFoundFromHeader 쿠키에서 토큰을 찾지 못했을 때 발생하는 예외입니다.
     * HttpStatus = 400.
     */
    private static final HttpStatus status = HttpStatus.BAD_REQUEST;

    public TokenNotFoundFromHeader(String message) {
        super(message);
    }

    public TokenNotFoundFromHeader() {
        super(DEFAULT_ERROR);
    }
}
