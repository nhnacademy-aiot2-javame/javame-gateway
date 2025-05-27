package com.nhnacademy.javamegateway.token;

import com.nhnacademy.javamegateway.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenValidatorTest {

    @Mock
    private RefreshTokenRepository tokenRepository;

    @Mock
    private ServerWebExchange exchange;

    @Mock
    private ServerHttpRequest request;

    private JwtTokenValidator jwtTokenValidator;

    @Value("${jwt.secret}")
    private String secretKey;

    private final String validAccessToken = "validAccessToken";
    private final String expiredAccessToken = "expiredAccessToken";
    private final String validRefreshToken = "validRefreshToken";
    private final String expiredRefreshToken = "expiredRefreshToken";


    @BeforeEach
    void setUp() {
        jwtTokenValidator = new JwtTokenValidator(secretKey, tokenRepository);
        when(exchange.getRequest()).thenReturn(request);
    }

    @Test
    @DisplayName("헤더에서 토큰 꺼내오기 성공.")
    void testResolveTokenFromHeader_withValidAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + validAccessToken);

        when(request.getHeaders()).thenReturn(headers);
        when(jwtTokenValidator.validateToken(validAccessToken)).thenReturn(true);

        String token = jwtTokenValidator.resolveTokenFromHeader(exchange);
        assertEquals(validAccessToken, token);
    }

    @Test
    @DisplayName("헤더에서 토큰 꺼내오기 실패.")
    void resolveTokenFromHeader_failed() {
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