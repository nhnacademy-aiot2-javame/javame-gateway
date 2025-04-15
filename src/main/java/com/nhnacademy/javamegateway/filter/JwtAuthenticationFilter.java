package com.nhnacademy.javamegateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.List;

@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final String secretKey;
    private final AntPathMatcher pathMatcher = new AntPathMatcher(); // <<<--- AntPathMatcher 인스턴스 생성

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    private static final List<String> WHITE_LIST = List.of(
            "/api/v1/auth/**"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        log.debug("Gateway JWT Filter: Path = {}", path);

        // --- 1. WHITE_LIST 경로인지 먼저 확인! (AntPathMatcher 사용) ---
        boolean isWhiteListed = WHITE_LIST.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path)); // <<<--- startsWith 대신 match 사용!
        log.debug("Gateway JWT Filter: isWhiteListed = {}", isWhiteListed); // 이제 true가 나와야 함!

        if (isWhiteListed) {
            log.debug("Gateway JWT Filter: Bypassing JWT validation for {}", path);
            return chain.filter(exchange);
        }

        // --- 2. WHITE_LIST 외의 경로만 토큰 검증 수행 ---
        log.debug("Gateway JWT Filter: Validating JWT for {}", path);
        String token = extractJwtFromRequest(request);

        if (token == null || !validateJwtToken(token)) {
            log.warn("Gateway JWT Filter: Unauthorized access attempt for {}", path);
            return unauthorizedResponse(exchange);
        }

        // --- 3. 토큰 유효 시 다음 필터 진행 ---
        log.debug("Gateway JWT Filter: JWT validation successful for {}", path);
        Claims claims = getClaimFromToken(token);
        if (claims != null) {
            exchange.getAttributes().put("claims", claims);
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1; // 높은 우선순위 유지
    }

    private Claims getClaimFromToken(String token) {
        try {
            byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
            return Jwts.parserBuilder()
                    .setSigningKey(secretKeyBytes)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    private String extractJwtFromRequest(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateJwtToken(String token) {
        try {
            byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
            Jwts.parserBuilder()
                    .setSigningKey(secretKeyBytes)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }
}
