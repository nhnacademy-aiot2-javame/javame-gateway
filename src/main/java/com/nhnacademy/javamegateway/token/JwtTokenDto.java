package com.nhnacademy.javamegateway.token;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * JWT 토큰 정보를 담는 DTO 클래스입니다.
 */
public class JwtTokenDto {
    /**
     * 액세스 토큰.
     *  액세스 토큰을 반환합니다.
     *
     * @return 액세스 토큰

     */
    @JsonProperty("accessToken")
    private String accessToken;

    /**
     * 리프레시 토큰.
     */
    @JsonProperty("refreshToken")
    private String refreshToken;

    /**
     * 기본 생성자.
     */
    public JwtTokenDto() {
    }

    /**
     * 모든 필드를 초기화하는 생성자입니다.
     *
     * @param accessToken  액세스 토큰
     * @param refreshToken 리프레시 토큰
     */
    public JwtTokenDto(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * AT를 반환합니다.
     * @return AT
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * 리프레시 토큰을 반환합니다.
     *
     * @return 리프레시 토큰
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public String toString() {
        return "JwtTokenDto{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof JwtTokenDto that)) return false;
        return Objects.equals(accessToken, that.accessToken) && Objects.equals(refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken);
    }
}
