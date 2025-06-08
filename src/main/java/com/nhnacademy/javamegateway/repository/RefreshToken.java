package com.nhnacademy.javamegateway.repository;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.util.Objects;

@RedisHash(value = "refreshToken", timeToLive = 604800)
public class RefreshToken {
    /**
     * Redis에 담길 RefreshToken의 Key값입니다.
     */
    @Id
    @JsonProperty
    private String id;

    /**
     *  Redis에 담길 RefreshToken의 value값 입니다.
     */
    @JsonProperty
    private String token;

    /**
     * 사용자를 대신하여 작업을 수행하는 소프트웨어. 특히 웹 브라우저 같은 클라이언트 소프트웨어를 의미합니다.
     */
    @JsonProperty
    private String userAgent;

    /**
     * 사용자의 IP 주소입니다.
     */
    @JsonProperty
    private String ip;


    public RefreshToken() {
        // NoArgsConstructor
    }

    public RefreshToken(String id, String token, String userAgent, String ip) {
        this.id = id;
        this.token = token;
        this.userAgent = userAgent;
        this.ip = ip;
    }

    public String getId() {
        return id;
    }

    public String getToken() {
        return token;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getIp() {
        return ip;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof RefreshToken that)) return false;
        return Objects.equals(id, that.id)
                && Objects.equals(token, that.token)
                && Objects.equals(userAgent, that.userAgent)
                && Objects.equals(ip, that.ip);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, token, userAgent, ip);
    }
}
