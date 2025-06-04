package com.nhnacademy.javamegateway;

import org.springframework.http.server.reactive.ServerHttpRequest;

public class IpUtil {

    public static String getClientIp(ServerHttpRequest request) {
        String ip = request.getHeaders().getFirst("X-Forwarded-For");
        if (isInvalid(ip)) {
            ip = request.getHeaders().getFirst("Proxy-Client-IP");
        }
        if (isInvalid(ip)) {
            ip = request.getHeaders().getFirst("WL-Proxy-Client-IP");
        }
        if (isInvalid(ip)) {
            ip = request.getHeaders().getFirst("HTTP_CLIENT_IP");
        }
        if (isInvalid(ip)) {
            ip = request.getHeaders().getFirst("HTTP_X_FORWARDED_FOR");
        }
        if (isInvalid(ip)) {
            ip = request.getRemoteAddress() != null ? request.getRemoteAddress().getAddress().getHostAddress() : null;
        }

        // X-Forwarded-For에 여러 IP가 있을 경우 첫 번째 것만 사용
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }

    private static boolean isInvalid(String ip) {
        return ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip);
    }
}
