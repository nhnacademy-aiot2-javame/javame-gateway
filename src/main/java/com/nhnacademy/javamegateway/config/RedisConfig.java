package com.nhnacademy.javamegateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;

@Configuration
@EnableRedisRepositories(basePackages = "com.nhnacademy.javamegateway.repository")
public class RedisConfig {

    /**
     * Redis의 호스트 주소입니다.
     */
    @Value("${spring.data.redis.host}")
    private String host;

    /**
     * Redis의 port 번호입니다.
     */
    @Value("${spring.data.redis.port}")
    private int port;

    /**
     * Redis 비밀번호입니다.
     */
    @Value("${spring.data.redis.password}")
    private String password;

    /**
     * Redis database index 번호입니다.
     */
    @Value("${spring.data.redis.database}")
    private int redisDatabase;

    /**
     *
     * @return Redis 서버와의 연결을 관리하는 팩토리를 반환합니다.
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName(host);
        config.setPort(port);
        config.setDatabase(redisDatabase);
        config.setPassword(RedisPassword.of(password));

        return new LettuceConnectionFactory(config);
    }

    /**
     * 주어진 객체를 자동으로 직렬화/역질렬화 하며 binary데이터를 Redis에 저장합니다.
     * 기본 설정은 JdkSerializationRedisSerializer입니다.
     *
     * StringRedisSerializer: binary 데이터로 저장되기 때문에 이를 String 으로 변환시켜주며(반대로도 가능) UTF-8 인코딩 방식을 사용한다.
     * GenericJackson2JsonRedisSerializer는 Redis에 저장되는 객체를 JSON 형식으로 직렬화하고, 역직렬화할 수 있도록 합니다.
     *
     * @return Redis data access code를 간소화 하기 위해 제공하는 클래스를 반환합니다.
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory());

        template.setValueSerializer(genericJackson2JsonRedisSerializer());
        template.setDefaultSerializer(genericJackson2JsonRedisSerializer());

        template.setHashKeySerializer(genericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(genericJackson2JsonRedisSerializer());

        template.setDefaultSerializer(genericJackson2JsonRedisSerializer());

        return template;
    }

    @Bean
    public GenericJackson2JsonRedisSerializer genericJackson2JsonRedisSerializer() {
        return new GenericJackson2JsonRedisSerializer();
    }
}
