package com.nhnacademy.javamegateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.javamegateway.dto.MemberResponse;
import com.nhnacademy.javamegateway.exception.MissingTokenException;
import com.nhnacademy.javamegateway.exception.TokenNotFoundFromHeader;
import com.nhnacademy.javamegateway.token.JwtTokenValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.OptionalInt;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Component
@Slf4j
public class CompanyDomainRewriteGlobalFilter implements GlobalFilter, Ordered {

    /**
     * HTTP 요청할 Client.
     */
    private final WebClient webClient;

    /**
     * Member에게 넘겨줄 email값을 쿠키에서 얻기 위한 validator.
     */
    private JwtTokenValidator jwtTokenValidator;

    public CompanyDomainRewriteGlobalFilter(@Qualifier("loadBalancedWebClient")WebClient.Builder
                                                    webClientBuilder,
                                            JwtTokenValidator jwtTokenValidator) {
        this.webClient = webClientBuilder.baseUrl("http://MEMBER-API").build();
        this.jwtTokenValidator = jwtTokenValidator;
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String query = exchange.getRequest().getURI().getQuery();

        // path가 ws로 시작한다면 처리 제외
        if (path.startsWith("/ws/")) {
            log.debug("CompanyDomain filter: Skipping WebSocket path: {}", path);
            return chain.filter(exchange);
        }

        //Path 경로에 company-domain이 없다면 넘긴다.
        if (!path.contains("companyDomain")) {
            return chain.filter(exchange);
        }

        // OptionalInt 는 java 8에서 추가된 기본형 int 전용 Optional 클래스이다.
        // path 경로를 / 기준으로 나누고 idxOpt 에는 company-domain이 위치한 index 값을 가지게 된다.
        String[] segments = path.split("/"); //api/v1/envrionment/company-domain
        String[] newSegments = Arrays.copyOfRange(segments, 3, segments.length);

        //api, v1, envrionment, company-domain
        OptionalInt idxOpt = IntStream.range(0, newSegments.length)
                .filter(i -> newSegments[i].equals("companyDomain"))
                .findFirst();

        if (idxOpt.isEmpty()) return chain.filter(exchange);

        int index = idxOpt.getAsInt();

        String token;
        try {
            token = jwtTokenValidator.resolveTokenFromHeader(exchange);
        } catch (TokenNotFoundFromHeader e) {
            return chain.filter(exchange);
        }

        String email;
        try {
            email = jwtTokenValidator.getUserEmailFromToken(token);
        } catch (MissingTokenException e) {
            return chain.filter(exchange);
        }

        // 이메일로 회사 도메인 조회
        return webClient.get()
                .uri("/members/me")
                .header("X-User-Email", email)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody -> {
                                    log.error("응답 에러 발생. 상태코드: {}, 바디: {}",
                                            clientResponse.statusCode(), errorBody);
                                    return Mono.error(new RuntimeException("요청 실패"));
                                }))
                .bodyToMono(String.class)
                .doOnNext(rawJson -> log.debug("받은 MemberResponse 원본 JSON: {}", rawJson))
                .flatMap(rawJson -> {
                    try {
                        MemberResponse member = new ObjectMapper().readValue(rawJson,
                                MemberResponse.class);
                        String realDomain = member.getCompanyDomain();
                        log.debug("real Domain: {}", realDomain);
                        newSegments[index] = realDomain;

                        // path 재조립 (절대 query 안붙임)
                        String newPath = Arrays.stream(newSegments)
                                .filter(s -> !s.isBlank())
                                .collect(Collectors.joining("/", "/", ""));

                        log.debug("new Path(only): {}", newPath);

                        // 쿼리는 mutate().path(newPath)에서 자동 전파됨.
                        ServerHttpRequest newRequest = exchange.getRequest()
                                .mutate()
                                .path(newPath)
                                .build();

                        log.debug("new Req {}", newRequest);

                        ServerWebExchange newExchange = exchange.mutate()
                                .request(newRequest)
                                .build();

                        log.debug("environment 로 보낼 새 경로: {}", newExchange);
                        return chain.filter(newExchange);
                    } catch (Exception e) {
                        log.error("MemberResponse 파싱 실패", e);
                        return chain.filter(exchange);
                    }
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
