package com.nhnacademy.javamegateway.token;

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
    private String refreshToken;

    public RefreshToken() {
        // NoArgsConstructor
    }

    public RefreshToken(String id, String refreshToken) {
        this.id = id;
        this.refreshToken = refreshToken;
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "id='" + id + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }

    public String getId() {
        return id;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof RefreshToken that)) return false;
        return Objects.equals(id, that.id) && Objects.equals(refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, refreshToken);
    }
}
