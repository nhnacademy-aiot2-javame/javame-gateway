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
                .route("auth-api", r -> r.path("/api/auth/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri("lb://AUTH-API"))
                .route("member-api", r -> r.path("/api/member/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri("lb://MEMBER-API"))
                .build();
    }
}
