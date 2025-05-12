package com.nhnacademy.javamegateway.exception;

import org.springframework.http.HttpStatus;

public class TokenExpiredException extends RuntimeException {
    /**
     * TokenExpiredException 은 토큰의 유효기간이 만료되었을 때 발생하는 예외입니다.
     * HttpStatus = 401.
     */
    private static final HttpStatus status = HttpStatus.UNAUTHORIZED;

    public TokenExpiredException(String message) {
        super(message);
    }

    public HttpStatus getStatus() {
        return status;
    }
}
