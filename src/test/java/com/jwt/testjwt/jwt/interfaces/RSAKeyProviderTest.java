package com.jwt.testjwt.jwt.interfaces;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class RSAKeyProviderTest {

    private RSAKeyProvider keyProvider;

    @BeforeEach
    void setUp() {
        keyProvider = new RSAKeyProviderImpl();
    }


    @Test
    @DisplayName("외부저장소에서 publicKeyID로 publicKey를 가져온다")
    void getPublicKeyById() {
        RSAPublicKey publicKey = keyProvider.getPublicKeyById("key1"); //
        Assertions.assertThat(publicKey).isNotNull();
    }

    @Test
    @DisplayName("유효하지 않은 키ID로 공개키 조회시 null을 반환")
    void getPublicKeyById_null() {
        RSAPublicKey publicKey = keyProvider.getPublicKeyById("invalidKey");
        Assertions.assertThat(publicKey).isNull();
    }

    @Test
    @DisplayName("개인키 조회")
    void getPrivateKey() {
        RSAPrivateKey privateKey = keyProvider.getPrivateKey();
        Assertions.assertThat(privateKey).isNotNull();
    }

    @Test
    @DisplayName("개인키 ID 조회 성공")
    void 개인키ID_조회_성공() {
        String privateKeyId = keyProvider.getPrivateKeyId();
        Assertions.assertThat(privateKeyId).isEqualTo("my-private-key-id");
    }


    static class RSAKeyProviderImpl implements RSAKeyProvider {

        private Map<String, String> publicKeyMap = new HashMap<>();
        private Map<String, String> privateKeyMap = new HashMap<>();
        private String privateKeyId = "my-private-key-id";

        public RSAKeyProviderImpl() {
            initializeKeys();
        }

        @Override
        public RSAPublicKey getPublicKeyById(String keyId) {
            return loadPublicKey(keyId);
        }

        @Override
        public RSAPrivateKey getPrivateKey() {
            return loadPrivateKey(privateKeyId);
        }

        @Override
        public String getPrivateKeyId() {
            return privateKeyId;
        }

        private void initializeKeys() {

            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

                String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

                publicKeyMap.put("key1", encodedPublicKey);
                privateKeyMap.put(privateKeyId, encodedPrivateKey);
            } catch (NoSuchAlgorithmException e) {
                log.error("error={}", e);
            }
        }

        private RSAPublicKey loadPublicKey(String keyId) {
            try {
                String publicKeyStr = publicKeyMap.get(keyId);
                byte[] decodedKey = Base64.getDecoder().decode(publicKeyStr);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPublicKey) kf.generatePublic(spec);
            } catch (Exception e) {
                log.error("error={}", e);
            }
            return null;
        }

        private RSAPrivateKey loadPrivateKey(String keyId) {
            try {
                String privateKeyStr = privateKeyMap.get(keyId);
                byte[] decodedKey = Base64.getDecoder().decode(privateKeyStr);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPrivateKey) kf.generatePrivate(spec);
            } catch (Exception e) {
                log.error("error={}", e);
            }
            return null;
        }
    }

}
