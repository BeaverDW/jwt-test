package com.jwt.testjwt.jwt;

import com.auth0.jwt.HeaderParams;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class JWTClassTest {


    @Test
    @DisplayName("decodeJwt()는 토큰의 서명을 확인하지 않으니 토큰이 확인된 경우에만 사용해야 한다")
    void decodeJWT() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        Algorithm algorithm = Algorithm.RSA512(privateKey);
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject("hello world")
                .sign(algorithm);
        JWT jwt = new JWT();

        //when
        DecodedJWT decodedJWT = jwt.decodeJwt(token);

        Assertions.assertThat(decodedJWT.getSubject()).isEqualTo("hello world");
    }

    @Test
    @DisplayName("decodeJwt()는 토큰의 일부에 각 jwt 부분의 잘못된 jwt 형식이 포함된 경우 예외를 발생한다")
    void decodeJWT_exception() throws NoSuchAlgorithmException {
        //given
        String invalidToken = "invalid.jwt.token";

        assertThrows(JWTDecodeException.class, () -> JWT.decode(invalidToken));
    }

    @Test
    @DisplayName("JWT.require()에 null 알고리즘을 전달하면 IllegalArgumentException을 던진다")
    void require_exception() {
        assertThrows(IllegalArgumentException.class, () -> JWT.require(null));

    }


}
