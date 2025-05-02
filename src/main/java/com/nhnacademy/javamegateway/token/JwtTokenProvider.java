package com.nhnacademy.javamegateway.token;
import com.nhnacademy.javamegateway.exception.GenerateTokenDtoException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.web.server.ServerWebExchange;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 * Jwt 토큰 생성을 위한 Provider 클래스.
 */
@Getter
@Slf4j
public class JwtTokenProvider {
    /**
     * Access Token 유효 시간 (30분).
     */
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;

    /**
     * Refresh Token 유효 시간 (7일).
     */
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;

    /**
     * java.io.Serializable: 객체를 파일로 저장하거나 네트워크를 통해 전송할 수 있도록 변환하는 인터페이스.
     * 객체를 "문자열"처럼 변환해줌.
     *  Key: 암호화에 사용되는 키를 저장하는 인터페이스
     */
    private final Key key;

    /**
     * application.properties or application.yml에서 jwt.secret값을 찾아 secretKey 변수에 넣음
     * Jwt 서명을 위한 HMAC-SHA 키 생성.
     * -> Key를 가지고 메시지 해쉬값(MAC)을 생성해서 내가 원하는 사용자로부터 메시지가 왔는지 판단.
     *
     * @param secretKey Base64로 인코딩된 비밀 키
     */
    public JwtTokenProvider(@Value("${jwt.secret}")String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); //디코딩
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 생성
    public JwtTokenDto generateTokenDto(String userEmail, String userRole) {
        if (StringUtils.isEmpty(userEmail)) {
            throw new GenerateTokenDtoException(userEmail);
        }
        if (StringUtils.isEmpty(userRole)) {
            throw new GenerateTokenDtoException(userRole);
        }

        Date now = new Date();
        Date exp = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME); //토큰 만료기간
        log.debug("Expiration Time: {}", exp);

        String accessToken = Jwts.builder()
                .subject(userEmail) // JWT 주체, 사용자 Email
                .claim("role", userRole)
                .issuedAt(now)
                .expiration(exp) // JWT 만료 시간 설정
                .signWith(key)
                .compact();
        log.debug("accessToken: {}", accessToken);

        String refreshToken = Jwts.builder()
                .subject(userEmail)
                .claim("role", userRole)
                .expiration(new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(key)
                .compact();
        log.debug("refreshToken: {}", refreshToken);

        return new JwtTokenDto(accessToken, refreshToken);
    }

    public String resolveTokenFromCookie(ServerWebExchange exchange) {
        HttpCookie tokenCookie = exchange.getRequest().getCookies().get("")
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().toLowerCase().contains("token")) {
                    return cookie.getValue();
                } else throw new TokenNotFoundFromCookie();
            }
        }
        return null;
    }

    public String getUserEmailFromToken(String accessToken) {
        if (StringUtils.isEmpty(accessToken)) {
            throw new MissingTokenException(accessToken);
        }
        Claims claims = parseClaims(accessToken);
        return claims.getSubject();
    }

    public String getRoleIdFromToken(String token) {
        if (StringUtils.isEmpty(token)) {
            throw new MissingTokenException(token);
        }
        Claims claims = parseClaims(token);
        return claims.get("role", String.class);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith((SecretKey) key).build().parseSignedClaims(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.debug("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.debug("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.debug("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.debug("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    private Claims parseClaims(String accessToken) {
        //JWT가 유효하지 않은 경우 JwtException이 발생함.
        try {
            return Jwts.parser()
                    //Key가 HMAC 알고리즘을 사용하면 비밀키로 서명하고, 검증할 때도 같은 키를 써야되기 때문에 비밀키로 검증해야함.
                    .verifyWith((SecretKey) key)
                    .build()
                    .parseSignedClaims(accessToken)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("JWT 토큰이 만료되었습니다: {}", e.getMessage());
            return e.getClaims();
        }
    }

}
