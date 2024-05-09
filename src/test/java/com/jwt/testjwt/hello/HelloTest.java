package com.jwt.testjwt.hello;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class HelloTest {


    @Test
    @DisplayName("rsa 알고리즘으로 jwt 토큰을 생성한다")
    void create() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String token = null;

        //when
        Algorithm algorithm = Algorithm.RSA512(publicKey, privateKey);
        token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);


        //then
        assertThat(token).isNotNull();
        log.info("Toeken = {}", token);
    }

    @Test
    @DisplayName("rsa 알고리즘으로 생성 된 jwt 토큰을 검증한다")
    void verify() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        Algorithm algorithm = Algorithm.RSA512(publicKey, privateKey);
        String token = JWT.create()
                .withIssuer("jwttest")
                .sign(algorithm);


        //when

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("jwttest")
                .build();
        DecodedJWT verify = verifier.verify(token);


        //then
        Assertions.assertThat(verify).isNotNull();
    }

    @Test
    @DisplayName("토큰검증시 알고리즘이 다르면 예외가 발생한다")
    void verify_exception_1() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        Algorithm algorithm256 = Algorithm.RSA256(publicKey, privateKey);
        String token = JWT.create()
                .withIssuer("jwttest")
                .sign(algorithm256);


        //when
        Algorithm algorithm512 = Algorithm.RSA512(publicKey, privateKey);
        JWTVerifier verifier = JWT.require(algorithm512)
                .withIssuer("jwttest")
                .build();

        //then
        assertThrows(JWTVerificationException.class, () -> verifier.verify(token));
    }


    @Test
    @DisplayName("토큰검증시 발행주체가 다르면 예외가 발생한다")
    void verify_exception_2() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        Algorithm algorithm512 = Algorithm.RSA512(publicKey, privateKey);
        String token = JWT.create()
                .withIssuer("https://other.com")
                .sign(algorithm512);


        //when
        JWTVerifier verifier = JWT.require(algorithm512)
                .withIssuer("jwttest")
                .build();

        //then
        assertThrows(JWTVerificationException.class, () -> verifier.verify(token));
    }

    @Test
    @DisplayName("토큰검증시 서명 된 개인키와 다른 공개키로 검증하면 예외가 발생한다")
    void verify_exception_3() throws NoSuchAlgorithmException {
        //given
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        KeyPair otherKeyPair = generator.genKeyPair();

        RSAPrivateCrtKey otherServerPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey serverPublicKey = (RSAPublicKey) otherKeyPair.getPublic();

        Algorithm otherAlgorithm = Algorithm.RSA512(otherServerPrivateKey);
        String token = JWT.create()
                .withIssuer("jwttest")
                .sign(otherAlgorithm);

        //when
        Algorithm algorithm512 = Algorithm.RSA512(serverPublicKey);
        JWTVerifier verifier = JWT.require(algorithm512)
                .withIssuer("jwttest")
                .build();

        //then
        assertThrows(JWTVerificationException.class, () -> verifier.verify(token));
    }


}
