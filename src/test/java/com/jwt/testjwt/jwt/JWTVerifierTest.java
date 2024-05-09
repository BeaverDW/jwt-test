package com.jwt.testjwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
public class JWTVerifierTest {

    @Test
    @DisplayName("JWTVerifier에 정의된 알고리즘과 일치하지 않는 토큰을 검증시 AlgorithmMismatchException 발생")
    void verifier_Exception1() {
        String secret = "secret";
        Algorithm algorithmHS256 = Algorithm.HMAC256(secret);
        Algorithm algorithmHS512 = Algorithm.HMAC512(secret);

        String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithmHS512);

        JWTVerifier verifier = JWT.require(algorithmHS256)
                .build();


        assertThrows(AlgorithmMismatchException.class, () -> {
            verifier.verify(token);
        });
    }

    @Test
    @DisplayName("JWTVerifier에 정의된 서명과 일치하지 않을 때 SignatureVerificationException 발생")
    void verifier_Exception2() {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256("wrongSecret"))
                .build();

        assertThrows(SignatureVerificationException.class, () -> {
            verifier.verify(token);
        });
    }

    @Test
    @DisplayName("토큰의 유효기간이 만료되었을 때 TokenExpiredException 발생.")
    void verifier_Exception3() {
        Instant pastTime = Instant.now().minusSeconds(3600);
        String token = JWT.create()
                .withIssuer("auth0")
                .withExpiresAt(Date.from(pastTime))
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret"))
                .build();

        assertThrows(TokenExpiredException.class, () -> {
            verifier.verify(token);
        });
    }


    @Test
    @DisplayName("검증하려는 클레임이 토큰에 없을때 MissingClaimException 발생")
    void verifier_Exception4() {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret"))
                .withClaim("role", "admin")
                .build();

        assertThrows(MissingClaimException.class, () -> {
            verifier.verify(token);
        });
    }

    @Test
    @DisplayName("토큰에 포함된 클레임이 예상한 값과 다를 때 IncorrectClaimException 발생")
    void whenClaimIncorrect_thenThrowIncorrectClaimException() {
        String token = JWT.create()
                .withIssuer("auth0")
                .withClaim("role", "user")
                .sign(Algorithm.HMAC256("secret"));

        com.auth0.jwt.JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret"))
                .withClaim("role", "admin")
                .build();

        assertThrows(IncorrectClaimException.class, () -> {
            verifier.verify(token);
        });
    }
}
