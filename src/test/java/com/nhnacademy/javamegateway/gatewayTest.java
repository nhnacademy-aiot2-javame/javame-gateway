//package com.nhnacademy.javamegateway;
//
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.test.web.reactive.server.WebTestClient;
//
//@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
//public class gatewayTest {
//    @Autowired
//    WebTestClient webTestClient;
//
//    @Test
//    @DisplayName("유효한 토큰 - 정상적으로 api 이동")
//    void testValidTokenShouldInjectHeader() {
//        webTestClient.get()
//                .uri("/api/auth/register")
//                .exchange()
//                .expectStatus().isOk();
//    }
//}
