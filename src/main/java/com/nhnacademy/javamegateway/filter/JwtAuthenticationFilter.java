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
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.List;

@Slf4j
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
        String path = request.getURI().getPath(); // <<<--- getPath().toString() 대신 getURI().getPath() 사용 권장
        log.debug("Gateway JWT Filter: Path = {}", path); // 로깅 추가 (Slf4j 필요)

        // --- 1. WHITE_LIST 경로인지 먼저 확인! ---
        boolean isWhiteListed = WHITE_LIST.stream().anyMatch(path::startsWith); // startsWith 사용 (하위 경로 포함) 또는 AntPathMatcher 사용
        log.debug("Gateway JWT Filter: isWhiteListed = {}", isWhiteListed);

        if (isWhiteListed) {
            log.debug("Gateway JWT Filter: Bypassing JWT validation for {}", path);
            // WHITE_LIST에 포함된 경로면 토큰 검증 없이 바로 다음 필터로 진행
            return chain.filter(exchange); // <<<--- 여기서 바로 통과!
        }

        // --- 2. WHITE_LIST 외의 경로만 토큰 검증 수행 ---
        log.debug("Gateway JWT Filter: Validating JWT for {}", path);
        String token = extractJwtFromRequest(request); // 토큰 추출

        // 토큰이 없거나 유효하지 않으면 401 반환
//        if (token == null || !validateJwtToken(token)) {
//            log.warn("Gateway JWT Filter: Unauthorized access attempt for {}", path);
//            return unauthorizedResponse(exchange); // <<<--- 여기서 401 처리
//        }

        // --- 3. 토큰 유효 시 추가 작업 (클레임 추출 등) 및 다음 필터 진행 ---
        log.debug("Gateway JWT Filter: JWT validation successful for {}", path);
        Claims claims = getClaimFromToken(token);
        if (claims != null) {
            // ServerWebExchange의 속성(attribute)에 클레임 저장
            exchange.getAttributes().put("claims", claims);

            // (선택) 클레임 정보를 다음 서비스로 전달하기 위해 요청 헤더에 추가
            // String userId = claims.getSubject(); // 예시: subject에 사용자 ID가 있다고 가정
            // ServerHttpRequest mutatedRequest = request.mutate()
            //         .header("X-User-Id", userId) // 커스텀 헤더
            //         .build();
            // return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        // 헤더 수정 없이 그냥 통과
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
