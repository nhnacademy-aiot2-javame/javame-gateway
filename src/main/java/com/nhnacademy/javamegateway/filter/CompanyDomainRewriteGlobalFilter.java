package com.nhnacademy.javamegateway.filter;

import com.nhnacademy.javamegateway.dto.MemberResponse;
import com.nhnacademy.javamegateway.exception.MissingTokenException;
import com.nhnacademy.javamegateway.exception.TokenNotFoundFromHeader;
import com.nhnacademy.javamegateway.token.JwtTokenValidator;
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
                                                    webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://MEMBER-API").build();
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        //Path 경로에 company-domain이 없다면 넘긴다.
        if (!path.contains("company-domain")) {
            return chain.filter(exchange);
        }

        // OptionalInt 는 java 8에서 추가된 기본형 int 전용 Optional 클래스이다.
        // path 경로를 / 기준으로 나누고 idxOpt 에는 company-domain이 위치한 index 값을 가지게 된다.
        String[] segments = path.split("/"); //api/v1/envrionment/company-domain
        //api, v1, envrionment, company-domain
        OptionalInt idxOpt = IntStream.range(0, segments.length)
                .filter(i -> segments[i].equals("company-domain"))
                .findFirst();

        if (idxOpt.isEmpty()) return chain.filter(exchange);

        int index  = idxOpt.getAsInt();

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
        return webClient.post()
                .uri("/member-email")
                .bodyValue(email)
                .retrieve() //요청을 전송하고 서버의 응답 받을 준비.
                .bodyToMono(MemberResponse.class) //응답 JSON을 역직렬화.
                .map(MemberResponse::getCompanyDomain)
                .flatMap(realDomain -> {
                    // 경로에 회사 도메인 치환
                    segments[index] = realDomain;

                    String newPath = Arrays.stream(segments)
                            .filter(s -> !s.isBlank())
                            .collect(Collectors.joining("/", "/", "/"));

                    ServerHttpRequest newRequest = exchange.getRequest()
                            .mutate()
                            .path(newPath)
                            .build();

                    ServerWebExchange newExchange = exchange.mutate()
                            .request(newRequest)
                            .build();

                    return chain.filter(newExchange);
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
