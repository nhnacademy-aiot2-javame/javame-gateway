package com.nhnacademy.javamegateway.exception;

public class AccessTokenReissueRequiredException extends RuntimeException {

    public AccessTokenReissueRequiredException(String message) {
        super(message);
    }
}
