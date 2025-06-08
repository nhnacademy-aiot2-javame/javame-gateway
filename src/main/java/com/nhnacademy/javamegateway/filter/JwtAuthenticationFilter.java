package com.nhnacademy.javamegateway.filter;

import com.nhnacademy.javamegateway.exception.AccessTokenReissueRequiredException;
import com.nhnacademy.javamegateway.exception.AuthenticationCredentialsNotFoundException;
import com.nhnacademy.javamegateway.exception.TokenExpiredException;
import com.nhnacademy.javamegateway.repository.RefreshTokenRepository;
import com.nhnacademy.javamegateway.token.JwtTokenDto;
import com.nhnacademy.javamegateway.token.JwtTokenValidator;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
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
     * HTTP 요청할 Client.
     */
    private WebClient webClient;

    /**
     * WebClientConfig에 설정해놓은 builder.
     */
    private final WebClient.Builder loadBalancedWebClient;

    /**
     * RefreshToken 저장소.
     */
    private final RefreshTokenRepository refreshTokenRepository;

    /**
     *  redis key 값에 추가할 prefix.
     */
    @Value("${token.prefix}")
    private String tokenPrefix;

    /**
     * WHITE LIST 에 들어가는 url.
     */
    private static final List<String> WHITE_LIST = List.of(
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/environment",
            "/api/v1/members/register",
            "/api/v1/members/register/owners",
            "/api/v1/companies/register",
            "/api/v1/auth/login"
    );

    @PostConstruct
    public void init() {
        // 여기서 실제 WebClient 인스턴스 생성
        this.webClient = loadBalancedWebClient.baseUrl("http://AUTH-API").build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // OPTIONS 요청은 CORS Preflight이므로 필터 통과
        if (request.getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }
        log.info("Gateway JWT Filter: Path = {}", path);

        if (exchange.getRequest().getURI().getPath().startsWith("/api/v1/ws/environment")) {
            log.debug("WebSocket path detected, applying WebSocket auth logic");
            return handleWebSocketAuthentication(exchange, chain);
        }

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

           // 1) X-Refresh-Token 헤더가 있으면, 이 요청은 토큰 재발급 요청으로 간주
        // 1) X-Refresh-Token 헤더가 있으면, 이 요청은 토큰 재발급 요청으로 간주
        String refreshTokenHeader = request.getHeaders().getFirst("X-Refresh-Token");
        if (StringUtils.hasText(refreshTokenHeader)) {
            //Refresh Token이 유효하지 않을 때
            String refreshToken = jwtTokenValidator.resolveRefreshTokenFromHeader(exchange);
            if (!jwtTokenValidator.validateToken(refreshToken)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.getHeaders().add("X-Refresh-Required", "true");
                return response.setComplete();
            }

            String userEmail = jwtTokenValidator.getUserEmailFromToken(refreshToken);
            String userRole = jwtTokenValidator.getRoleIdFromToken(refreshToken);

            log.info("---Refresh_Token_재발급---");

            return webClient.get()
                    .uri("/auth/refresh")
                    .header("X-User-Email", userEmail)
                    .header("X-User-Role", userRole)
                    .header("X-Refresh-Token", refreshToken)
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                            clientResponse -> clientResponse.bodyToMono(JwtTokenDto.class)
                                    .flatMap(errorBody -> {
                                        log.error("응답 에러 발생. 상태코드: {}, 바디: {}",
                                                clientResponse.statusCode(), errorBody);
                                        return Mono.error(new RuntimeException("요청 실패"));
                                    }))
                    .bodyToMono(JwtTokenDto.class)
                    .flatMap(jwtTokenDto -> {
                        // 받은 accessToken, refreshToken으로 response 헤더 세팅
                        ServerHttpResponse response = exchange.getResponse();
                        response.getHeaders().set("Authorization",
                                "Bearer " + jwtTokenDto.getAccessToken());
                        response.getHeaders().set("X-Refresh-Token", jwtTokenDto.getRefreshToken());
                        response.setStatusCode(HttpStatus.OK);
                        return response.setComplete();
                    });
        }

        try {
            String token = jwtTokenValidator.resolveTokenFromHeader(exchange);
            if (!jwtTokenValidator.validateToken(token)) {
                throw new AccessTokenReissueRequiredException("Access token expired or invalid.");
            }
            String role = jwtTokenValidator.getRoleIdFromToken(token);
            String userEmail = jwtTokenValidator.getUserEmailFromToken(token);

            ServerHttpRequest mutateRequest = request.mutate()
                    .header("X-User-Role", role)
                    .header("X-User-Email", userEmail)
                    .build();

            return chain.filter(exchange.mutate().request(mutateRequest).build());
        } catch (AccessTokenReissueRequiredException ex) {
            log.debug("Access token expired. Checking refresh token...");

            String refreshToken = jwtTokenValidator.resolveRefreshTokenFromHeader(exchange);
            //Refresh Token이 없을 때
            if (!StringUtils.hasText(refreshToken)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.getHeaders().add("X-Refresh-Required", "true");
                return response.setComplete();
            }

            // refresh token 유효성 검증 및 재발급 처리 로직 (위에서 X-Refresh-Token 헤더 있을 때 처리했던 것과 유사)
            if (!jwtTokenValidator.validateToken(refreshToken)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.getHeaders().add("X-Refresh-Required", "true");
                return response.setComplete();
            }

            // refreshToken에서 이메일, 역할 등 꺼내기
            String userEmail = jwtTokenValidator.getUserEmailFromToken(refreshToken);
            String userRole = jwtTokenValidator.getRoleIdFromToken(refreshToken);
            // refreshToken DB 체크 및 IP, UA 검증 등

            // (필요시) mutate 요청 경로, 헤더 변경 후 체인에 넘기기
            ServerHttpRequest refreshRequest = request.mutate()
                    .path("/auth/refresh")
                    .header("X-User-Email", userEmail)
                    .header("X-User-Role", userRole)
                    .build();

            return chain.filter(exchange.mutate().request(refreshRequest).build());

        } catch (TokenExpiredException ex) {
            log.debug("Both tokens expired. Login required. ");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add("X-Reauth-Required", "true");
            return exchange.getResponse().setComplete();
        } catch (AuthenticationCredentialsNotFoundException ex) {
            log.debug("No token found in headers");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().add("X-Token-Required", "true");
            return exchange.getResponse().setComplete();
        }
    }

    private Mono<Void> handleWebSocketAuthentication(ServerWebExchange exchange,
                                                     GatewayFilterChain chain) {
        try {
            String token = extractTokenFromQuery(exchange);
            if (token != null && jwtTokenValidator.validateToken(token)) {
                String role = jwtTokenValidator.getRoleIdFromToken(token);
                String userEmail = jwtTokenValidator.getUserEmailFromToken(token);

                ServerHttpRequest mutateRequest = exchange.getRequest().mutate()
                        .header("X-User-Role", role)
                        .header("X-User-Email", userEmail)
                        .header("X-WebSocket-Auth", "validated")
                        .build();

                log.debug("WebSocket authentication successful for user: {}", userEmail);

                return chain.filter(exchange.mutate().request(mutateRequest).build());
            } else {
                log.warn("WebSocket authentication failed - invalid or missing token");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        } catch (Exception ex) {
            log.error("WebSocket authentication error", ex);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private String extractTokenFromQuery(ServerWebExchange exchange) {
        String query = exchange.getRequest().getURI().getQuery();
        if (query != null && query.contains("token=")) {
            String[] params = query.split("&");
            for (String param : params) {
                if (param.startsWith("token=")) {
                    return param.substring(6);
                }
            }
        }
        return null;
    }

    @Override
    public int getOrder() {
        return -3;
    }
}
