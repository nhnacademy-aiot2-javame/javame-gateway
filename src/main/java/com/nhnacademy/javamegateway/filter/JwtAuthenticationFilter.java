package com.nhnacademy.javamegateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Base64;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final String secretKey;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 요청에서 JWT 토큰을 추출
        ServerHttpRequest request = exchange.getRequest();
        String token = extractJwtFromRequest(request);

        //JWT 토큰이 없으면 401 Unauthorized 에러를 반환
        if (token == null) {
            return unauthorizedResponse(exchange);
        }

        // JWT 토큰이 있으면 검증
        if (validateJwtToken(token)) {
            Claims claims = getClaimFromToken(token);
            if (claims != null) {
                // 인증 정보 설정 (예: 사용자 ID, 권한 등)
                exchange.getAttributes().put("claims", claims);
            }
        } else {
            return unauthorizedResponse(exchange);
        }

        return chain.filter(exchange);
    }

    private Claims getClaimFromToken(String token) {
        byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKeyBytes)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    // 요청에서 JWT 토큰을 추출하는 메서드
    private String extractJwtFromRequest(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 이후의 토큰 문자열 반환
        }
        return null;
    }

    // JWT 토큰을 검증하는 메서드
    private boolean validateJwtToken(String token) {
        try {
            byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
            Jwts.parserBuilder()
                    .setSigningKey(secretKeyBytes) // 시그니처 검증을  위한 비밀키 설정
                    .build()
                    .parseClaimsJws(token); // 유효한 토큰인 경우 정상적으로 파싱됨
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 401 Unauthorized 에러를 반환하는 메서드
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();

    }

}
