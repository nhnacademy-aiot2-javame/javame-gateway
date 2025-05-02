package com.nhnacademy.javamegateway.exception;

public class GenerateTokenDtoException extends RuntimeException {
    public GenerateTokenDtoException(String tokenDto) {
        super(String.format("%s is empty.", tokenDto));
    }
}
