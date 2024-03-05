package com.akshayedusource.vaultIntergration.service;

import com.akshayedusource.vaultIntergration.exceptions.TokenExpiredException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Data
@Slf4j
public class JwtValidationService {

    @Autowired
    RestTemplate restTemplate;

    public static final String WELL_KNOWN_KEYS_ENDPOINT="/.well-known/keys";

    private static final Logger log = LoggerFactory.getLogger(JwtValidationService.class);


    public boolean validateJwtToken(String jwtToken){
        try {
            log.debug("Validating JWT token...");
            DecodedJWT decodedJWT = JWT.decode(jwtToken);
            String issuer = decodedJWT.getIssuer();
            log.debug("Validating JWT token issued by: {}", issuer);

            String kid = decodedJWT.getKeyId();
            log.debug("Key ID (kid) extracted from JWT: {}", kid);

            Date expirationTime = decodedJWT.getExpiresAt();
            if (expirationTime != null && expirationTime.before(new Date())) {
                log.warn("JWT token has expired. Expiration time: {}", expirationTime);
                throw new TokenExpiredException("JWT token has expired");
            }

            List<Map<String, String>> wellKnownKeys = getWellKnownKeysFromIssuer(issuer);
            log.debug("Retrieved well-known keys from issuer: {}", wellKnownKeys);

            Map<String, String> publicKeyMap = wellKnownKeys.stream()
                    .filter(key -> kid.equals(key.get("kid")))
                    .findFirst()
                    .orElse(null);

            if (publicKeyMap == null) {
                log.warn("No matching public key found for kid: {}", kid);
                return false;
            }

            RSAPublicKey publicKey = getPublicKey(publicKeyMap);
            if (publicKey == null) {
                log.error("Error obtaining RSA public key for kid: {}", kid);
                return false;
            }

            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            algorithm.verify(decodedJWT);



            log.info("JWT token validated successfully.");
            return true;
        } catch (JWTVerificationException e) {
            log.warn("JWT token validation failed: {}", e.getMessage());
            throw new JWTVerificationException("JWT token validation failed");
        } catch (TokenExpiredException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error occurred during JWT token validation: {}", e.getMessage());
            throw new RuntimeException("Error occurred during JWT token validation");
        }
    }





    @Cacheable(value = "wellKnownKeysCache", key = "#issuer")
    private List<Map<String, String>> getWellKnownKeysFromIssuer(String issuer) {
        String wellKnownKeysUrl = issuer + WELL_KNOWN_KEYS_ENDPOINT;
        try {
            log.debug("Fetching well-known keys from: {}", wellKnownKeysUrl);
            ResponseEntity<Map[]> responseEntity = restTemplate.getForEntity(wellKnownKeysUrl, Map[].class);
            Map<String, String>[] responseBody = responseEntity.getBody();

            if (responseBody == null || responseBody.length == 0) {
                log.error("Failed to fetch well-known keys from {}", wellKnownKeysUrl);
                throw new IllegalStateException("Failed to fetch well-known keys");
            }

            List<Map<String, String>> keys = Arrays.asList(responseBody);
            log.debug("Well-known keys fetched successfully.");
            return keys;
        } catch (Exception e) {
            log.error("Error occurred while fetching well-known keys: {}", e.getMessage());
            throw new IllegalStateException("Failed to fetch well-known keys", e);
        }
    }



    private RSAPublicKey getPublicKey(Map<String, String> wellKnownKey) {
        try {
            log.debug("Extracting RSA public key from well-known key: {}", wellKnownKey);

            if (wellKnownKey != null && !wellKnownKey.isEmpty()) {
                String kty = wellKnownKey.get("kty");
                String modulus = wellKnownKey.get("n");
                String exponent = wellKnownKey.get("e");

                if ("RSA".equals(kty)) {
                    byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
                    byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);

                    BigInteger modulusInt = new BigInteger(1, modulusBytes);
                    BigInteger exponentInt = new BigInteger(1, exponentBytes);

                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusInt, exponentInt);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(keySpec);

                    if (publicKey instanceof RSAPublicKey) {
                        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                        log.debug("RSA public key extracted successfully: {}", rsaPublicKey);
                        return rsaPublicKey;
                    }
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Error occurred while extracting RSA public key: {}", e.getMessage());
        }

        log.warn("Failed to extract RSA public key from well-known key: {}", wellKnownKey);
        return null;
    }


    public List<String> getClaims(String token) {
        SignedJWT signedJWT = null;
        try {
            log.debug("Parsing JWT token to extract claims...");
            signedJWT = SignedJWT.parse(token);

            List<String> claims = signedJWT.getJWTClaimsSet().getStringListClaim("groups").stream()
                    .map(s -> "ROLE_" + s)
                    .collect(Collectors.toList());

            log.debug("Claims extracted successfully: {}", claims);
            return claims;
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT token: {}", e.getMessage());
            return null;
        }
    }
}
