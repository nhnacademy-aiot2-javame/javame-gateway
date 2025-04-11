package com.nhnacademy.javamegateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final String secretKey;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    private static final List<String> WHITE_LIST = List.of(
            "/api/auth/register",
            "/api/auth/login"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = exchange.getRequest().getPath().toString();
        String token = extractJwtFromRequest(request);

        if (WHITE_LIST.contains(path)) {
            return chain.filter(exchange);
        }

        if (token == null || !validateJwtToken(token)) {
            return unauthorizedResponse(exchange);
        }

        Claims claims = getClaimFromToken(token);
        if (claims != null) {
            exchange.getAttributes().put("claims", claims);
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1;
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
