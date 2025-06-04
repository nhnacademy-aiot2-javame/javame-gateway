package com.nhnacademy.javamegateway.exception;

public class RefreshTokenNotFoundException extends RuntimeException {
    public RefreshTokenNotFoundException(String message) {
        super(String.format("%s not found in RefreshTokenException", message));
    }
}
