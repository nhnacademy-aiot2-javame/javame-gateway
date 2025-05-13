package com.nhnacademy.javamegateway.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtTokenValidatorTest {

    @Test
    @DisplayName("쿠키에서 토큰 꺼내오기 성공.")
    void resolveTokenFromCookie_successes() {
    }

    @Test
    @DisplayName("쿠키에서 토큰 꺼내오기 실패.")
    void resolveTokenFromCookie_failed() {
    }

    @Test
    @DisplayName("토큰에서 이메일 가져오기 성공.")
    void getUserEmailFromToken_successes() {
    }

    @Test
    @DisplayName("토큰에서 이메일 가져오기 실패.")
    void getUserEmailFromToken_failed() {
    }

    @Test
    @DisplayName("토큰에서 role 값 가져오기 성공.")
    void getRoleIdFromToken_success() {
    }

    @Test
    @DisplayName("토큰에서 role 값 가져오기 실패.")
    void getRoleIdFromToken_failed() {
    }

    @Test
    @DisplayName("Redis 에서 Refresh 토큰 값 검증.")
    void validateRefreshFromRedis() {
    }

    @Test
    void validateToken() {
    }

    @Test
    void getKey() {
    }

    @Test
    void getTokenPrefix() {
    }

    @Test
    void getTokenRepository() {
    }
}