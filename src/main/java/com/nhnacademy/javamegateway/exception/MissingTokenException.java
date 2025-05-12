package com.nhnacademy.javamegateway.exception;

import org.springframework.http.HttpStatus;

public class MissingTokenException extends RuntimeException {
    /**
     * MissingTokenException front 에서 토큰을 받지 못했을 때 발생하는 예외입니다.
     * HttpStatus = 401.
     */
    private static final HttpStatus status = HttpStatus.UNAUTHORIZED;

    public MissingTokenException(String token) {
        super(String.format("%s is missing from the request.", token));
    }

    public HttpStatus getStatus() {
        return status;
    }
}
