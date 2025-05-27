package com.nhnacademy.javamegateway.filter;

import com.nhnacademy.javamegateway.exception.AccessTokenReissueRequiredException;
import com.nhnacademy.javamegateway.exception.AuthenticationCredentialsNotFoundException;
import com.nhnacademy.javamegateway.exception.TokenExpiredException;
import com.nhnacademy.javamegateway.token.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    /**
     * 토큰 검증 및 파서역할자.
     */
    private final JwtTokenValidator jwtTokenValidator;


    /**
     * WHITE LIST 에 들어가는 url.
     */
    private static final List<String> WHITE_LIST = List.of(
            "/api/v1/members/register",
            "/api/v1/members/register/owners",
            "/api/v1/companies/register",
            "/api/v1/auth/login"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        log.debug("Gateway JWT Filter: Path = {}", path);

        // --- 1. WHITE_LIST 경로인지 먼저 확인! ---
        boolean isWhiteListed = WHITE_LIST.stream().anyMatch(path::startsWith);
        log.debug("Gateway JWT Filter: isWhiteListed = {}", isWhiteListed);

        if (isWhiteListed) {
            log.debug("Gateway JWT Filter: Bypassing JWT validation for {}", path);
            // WHITE_LIST에 포함된 경로면 토큰 검증 없이 바로 다음 필터로 진행
            return chain.filter(exchange);
        }

        // --- 2. WHITE_LIST 외의 경로만 토큰 검증 수행 ---
        log.debug("Gateway JWT Filter: Validating JWT for {}", path);

        try {
            String token = jwtTokenValidator.resolveTokenFromHeader(exchange);

            String role = jwtTokenValidator.getRoleIdFromToken(token);
            String userEmail = jwtTokenValidator.getUserEmailFromToken(token);

            ServerHttpRequest mutateRequest = request.mutate()
                    .header("X-User-Role", role)
                    .header("X-User-Email", userEmail)
                    .build();

            return chain.filter(exchange.mutate().request(mutateRequest).build());

        } catch (AccessTokenReissueRequiredException ex) {
            log.debug("Access Token expired but refresh token valid. Reissue required.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add("X-Reissue-Required", "true");
            return exchange.getResponse().setComplete();
        } catch (TokenExpiredException ex) {
            log.debug("Both tokens expired. Login required. ");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add("X-Reauth-Required", "true");
            return exchange.getResponse().setComplete();
        } catch (AuthenticationCredentialsNotFoundException ex) {
            log.debug("No token found in cookies");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add("X-Token-Required", "true");
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -3;
    }
}
