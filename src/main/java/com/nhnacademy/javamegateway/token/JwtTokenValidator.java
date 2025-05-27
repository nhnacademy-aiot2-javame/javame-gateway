package com.nhnacademy.javamegateway.token;

import com.nhnacademy.javamegateway.exception.AccessTokenReissueRequiredException;
import com.nhnacademy.javamegateway.exception.AuthenticationCredentialsNotFoundException;
import com.nhnacademy.javamegateway.exception.MissingTokenException;
import com.nhnacademy.javamegateway.exception.ServerWebExchangeIsNull;
import com.nhnacademy.javamegateway.exception.TokenExpiredException;
import com.nhnacademy.javamegateway.repository.RefreshTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Objects;

/**
 * Jwt 토큰 생성을 위한 Provider 클래스.
 */
@Getter
@Slf4j
@Component
public class JwtTokenValidator {
    /**
     * java.io.Serializable: 객체를 파일로 저장하거나 네트워크를 통해 전송할 수 있도록 변환하는 인터페이스.
     * 객체를 "문자열"처럼 변환해줌.
     *  Key: 암호화에 사용되는 키를 저장하는 인터페이스
     */
    private final Key key;

    /**
     *  redis key 값에 추가할 prefix.
     */
    @Value("${token.prefix}")
    private String tokenPrefix;

    /**
     * Refresh Token 검증을 위한 Repository.
     */
    private final RefreshTokenRepository tokenRepository;


    /**
     *  Bearer 문자열을 상수로 정의.
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * application.properties or application.yml에서 jwt.secret값을 찾아 secretKey 변수에 넣음
     * Jwt 서명을 위한 HMAC-SHA 키 생성.
     * -> Key를 가지고 메시지 해쉬값(MAC)을 생성해서 내가 원하는 사용자로부터 메시지가 왔는지 판단.
     *
     * @param secretKey Base64로 인코딩된 비밀 키
     * @param tokenRepository Redis와 연동한 Refresh Token Repository.
     */
    public JwtTokenValidator(@Value("${jwt.secret}")String secretKey,
                             RefreshTokenRepository tokenRepository) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); //디코딩
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.tokenRepository = tokenRepository;
    }

    /**
     * front 에서 HttpOnlyCookie로 넘겨준 accessToken, refreshToken을 꺼내 넘깁니다.
     *
     * @param exchange Gateway 에서 사용하는 WebFlux 전용 객체.
     * @return Cookie 에서 추출한 토큰.
     */
    public String resolveTokenFromHeader(ServerWebExchange exchange) {
        if (Objects.isNull(exchange)) {
            throw new ServerWebExchangeIsNull("들어온 요청 값이 없습니다.");
        }
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        String refreshTokenHeader = headers.getFirst("Refresh-Token");

        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String accessToken = authorizationHeader.substring(BEARER_PREFIX.length());
            if (validateToken(accessToken)) {
                return accessToken;
            } else {
                // accessToken 만료됨
                throw new TokenExpiredException("AccessToken expired");
            }
        }
        // 2. RefreshToken 처리
        if (refreshTokenHeader != null) {
            if (validateRefreshFromRedis(refreshTokenHeader) && validateToken(refreshTokenHeader)) {
                throw new AccessTokenReissueRequiredException(
                        "Access token expired, but refresh token valid"
                );
            } else {
                throw new TokenExpiredException("Refresh token expired");
            }
        }
        throw new AuthenticationCredentialsNotFoundException("No token found in cookies");
    }

    /**
     *
     * @param token 쿠키에서 꺼낸 토큰입니다.
     * @return 토큰에서 사용자 이메일값을 반환하는 메소드입니다.
     */
    public String getUserEmailFromToken(String token) {
        validateTokenPresence(token);
        Claims claims = parseValidClaims(token);
        return claims.getSubject();
    }

    /**
     *
     * @param token 쿠키에서 꺼낸 토큰입니다.
     * @return 토큰에서 사용자 역할을 반환하는 메소드입니다.
     */
    public String getRoleIdFromToken(String token) {
        validateTokenPresence(token);
        Claims claims = parseValidClaims(token);
        return claims.get("role", String.class);
    }

    /**
     * Redis에 존재하는 Refresh 토큰인지 검증합니다. 여기서 false 값이 나오면 이미 삭제한 Refresh 토큰입니다.
     * @param refreshToken 검증할 refreshToken.
     * @return true, false.
     */
    public boolean validateRefreshFromRedis(String refreshToken) {
        validateTokenPresence(refreshToken);
        String userId = getUserEmailFromToken(refreshToken);
        String refreshTokenId = DigestUtils.sha256Hex(tokenPrefix + ":" + userId);
        return tokenRepository.existsById(refreshTokenId);
    }

    /**
     * jwt token이 유효한지, 서명이 올바른지 등에 대해 검증하는 메소드입니다.
     * @param token 쿠키에서 꺼낸 토큰입니다.
     * @return true, false를 반환합니다.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith((SecretKey) key).build().parseSignedClaims(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.warn("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    /**
     * 토큰 값이 비어있는지 null 값인지 검증하는 메소드입니다.
     * @param token 쿠키에서 꺼낸 토큰값입니다.
     */
    private void validateTokenPresence(String token) {
        if (token == null || token.isBlank()) {
            throw new MissingTokenException(token);
        }
    }

    /**
     * JWT를 Parse 하는 메소드입니다.
     * @param token 쿠키에서 꺼낸 jwt 토큰입니다.
     * @return 정보값이 들어있는 claims를 반환합니다.
     */
    private Claims parseValidClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith((SecretKey) key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("JWT 토큰이 만료되었습니다: {}", e.getMessage());
            return e.getClaims();
        }
    }
}
