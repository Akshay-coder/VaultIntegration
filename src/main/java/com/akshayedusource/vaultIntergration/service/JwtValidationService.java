package com.akshayedusource.vaultIntergration.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Service
@Data
public class JwtValidationService {

    @Value("${jwt.issuer}")
    private String expectedIssuer;

    @Value("${jwt.namespace}")
    private String expectedNamespace;

    @Autowired
    private VaultTemplate vaultTemplate;

    @Autowired
    private CacheManager cacheManager;

    public boolean validateJwtToken(String jwtToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            String issuer = signedJWT.getJWTClaimsSet().getStringClaim("issuer");

            if (!expectedIssuer.equals(issuer)) {
                return false;
            }

            String namespace = signedJWT.getJWTClaimsSet().getStringClaim("namespace");

            if (!expectedNamespace.equals(namespace)) {
                return false;
            }

            List<String> keys = getWellKnownKeys(namespace);

            if(!validateJwtToken(jwtToken,keys)){
                return false;
            }


            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public List<String> getClaims(String token) {
        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getStringListClaim("groups").stream().map(s -> "ROLE_"+s).collect(Collectors.toList());
        } catch (ParseException e) {
           e.printStackTrace();
           return null;
        }

    }

    @Cacheable(value = "wellKnownKeysCache", key = "#namespace")
    public List<String> getWellKnownKeys(String namespace) {
        VaultResponse response = vaultTemplate.read("secret/well-known-keys/" + namespace);

        if (response != null && response.getData() != null) {
            Map<String, Object> data = response.getData();
            List<String> wellKnownKeys = (List<String>) data.get("keys");
            return wellKnownKeys;
        } else {
            return new ArrayList<>();
        }

    }

    public boolean validateJwtToken(String jwtToken, List<String> wellKnownKeys) {
        try {
            for (String publicKey : wellKnownKeys) {
                byte[] decodedPublicKey = Base64.getDecoder().decode(publicKey);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedPublicKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
                Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, null);

                JWTVerifier verifier = JWT.require(algorithm).build();

                verifier.verify(jwtToken);

                return true;
            }
        } catch (JWTVerificationException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void evictCache() {
        cacheManager.getCache("wellKnownKeysCache").clear();
    }
}
