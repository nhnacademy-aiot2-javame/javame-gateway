package com.nhnacademy.javamegateway.token;

import com.nhnacademy.javamegateway.exception.ServerWebExchangeIsNull;
import com.nhnacademy.javamegateway.exception.TokenExpiredException;
import com.nhnacademy.javamegateway.repository.RefreshTokenRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private final String secretKey = "dXNlLWFjdHVhbC1iYXNlNjQtZW5jb2RlZC1zZWNyZXQdXNlLWFjdHVhbC1i=";
    private final String validAccessToken = "validAccessToken";
    private final String expiredAccessToken = "expiredAccessToken";
    private final String validRefreshToken = "validRefreshToken";
    private final String expiredRefreshToken = "expiredRefreshToken";

    String validJwt = Jwts.builder()
            .setSubject("test-user")
            .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)))
            .compact();


    @BeforeEach
    void setUp() {
        jwtTokenValidator = new JwtTokenValidator(secretKey, tokenRepository);
    }

    @Test
    @DisplayName("헤더에서 토큰 꺼내오기 성공.")
    void testResolveTokenFromHeader_withValidAccessToken() {
        when(exchange.getRequest()).thenReturn(request);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + validJwt);

        when(request.getHeaders()).thenReturn(headers);
        // 실제 메서드 호출
        String token = jwtTokenValidator.resolveTokenFromHeader(exchange);

        // 기대한 결과와 실제 결과를 비교
        assertEquals(validJwt, token);
    }

    @Test
    @DisplayName("헤더에서 토큰 꺼내오기 실패 by excahgne가 null일때. ")
    void resolveTokenFromHeader_failed_ExchangeIsNull() {
        assertThrows(ServerWebExchangeIsNull.class, ()->{
            jwtTokenValidator.resolveTokenFromHeader(null);
        });
    }

    @Test
    @DisplayName("헤더에서 토큰 꺼내오기 실패 by accessToken이 만료되었을 떄. ")
    void resolveTokenFromHeader_failedAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + expiredAccessToken);

        when(request.getHeaders()).thenReturn(headers);

        // validateToken이 false를 반환하도록 설정
        when(jwtTokenValidator.validateToken(expiredAccessToken)).thenReturn(false);

        // TokenExpiredException이 발생하는지 검증
        assertThrows(TokenExpiredException.class, () -> {
            jwtTokenValidator.resolveTokenFromHeader(exchange);
        });
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