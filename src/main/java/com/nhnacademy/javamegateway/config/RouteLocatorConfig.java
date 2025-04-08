package com.nhnacademy.javamegateway.config;

import com.nhnacademy.javamegateway.filter.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public RouteLocatorConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public RouteLocator myRoute(RouteLocatorBuilder builder) {

        return builder.routes()
                .route("member-api",
                        predicateSpec -> predicateSpec.path("/api/member/**")
                                .uri("lb://MEMBER-API")
                )
                .route("auth-api",
                        predicateSpec -> predicateSpec.path("/api/auth/**")
                                .uri("lb:AUTH-API//")
                )
                .build();
    }
}
