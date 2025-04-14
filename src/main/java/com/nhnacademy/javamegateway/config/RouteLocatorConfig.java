package com.nhnacademy.javamegateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // --- Auth API 라우트 ---
                .route("auth-api", r -> r.path("/api/auth/**") // 외부 경로: /api/auth/**
                        .filters(f -> f.stripPrefix(1))        // /api 제거 -> 내부 경로: /auth/** (AUTH-API)
                        .uri("lb://AUTH-API"))


                // --- MemberController (CRUD)용 라우트 ---
                .route("member-api-crud", r -> r.path("/api/v1/members/**") // 외부 경로: /api/v1/members/**
                        // 외부 경로와 MemberController의 내부 경로가 동일하므로, 경로 변경 필터 불필요.
                        // 요청을 그대로 MEMBER-API로 전달합니다.
                        .uri("lb://MEMBER-API")) // 대상: MEMBER-API (MemberController가 /api/v1/members/** 처리)



                // 추가: LoginController (로그인 정보 조회)용 라우트
                .route("member-api-login", r -> r.path("/api/v1/login/**") // 외부 경로: /api/v1/login/** (이렇게 외부 노출하기로 결정)
                        // 필터: 외부 경로 '/api/v1/login/' 부분을 내부 경로 '/login/'으로 변경
                        // 정규식 설명:
                        //   /api/v1/login/(?<segment>.*) : /api/v1/login/ 다음에 오는 모든 문자열을 "segment"라는 이름으로 캡처
                        //   /login/${segment} : 캡처된 "segment" 문자열을 /login/ 뒤에 붙여서 새로운 경로 생성
                        .filters(f -> f.rewritePath("/api/v1/login/(?<segment>.*)", "/login/${segment}"))
                        .uri("lb://MEMBER-API")) // 대상: MEMBER-API (LoginController가 /login/** 처리)

                // 추가 : SensorController (센서 CRUD)용 라우트
                .route("iot-api", r -> r.path("/api/sensors")
                        .uri("lb://JAVAME-TESTIOTSENSOR"))
                .build();
    }
}
