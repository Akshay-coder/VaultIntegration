package com.akshayedusource.vaultIntergration.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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
    private CacheManager cacheManager;

    @Autowired
    RestTemplate restTemplate;

    public boolean validateJwtToken(String jwtToken) {
        try {
            DecodedJWT decodedJWT = JWT.decode(jwtToken);
            String issuer = decodedJWT.getIssuer();

            List<String> wellKnownKeys = getWellKnownKeysFromIssuer(issuer);

            RSAPublicKey publicKey = getPublicKey(wellKnownKeys);
            if (publicKey == null) {
                return false;
            }

            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            algorithm.verify(decodedJWT);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Cacheable(value = "wellKnownKeysCache", key = "#issuer")
    private List<String> getWellKnownKeysFromIssuer(String issuer) {
        String wellKnownKeysUrl = issuer;
        ResponseEntity<Map> responseEntity;
        responseEntity = restTemplate.getForEntity(wellKnownKeysUrl, Map.class);
        List<String> wellKnownKeys = new ArrayList<>();

        List<Map<String, String>> keys = (List<Map<String, String>>) responseEntity.getBody().get("keys");

        if (keys != null) {
            for (Map<String, String> key : keys) {
                String kty = key.get("kty");
                String n = key.get("n");
                String e = key.get("e");

                if ("RSA".equals(kty)) {
                    String publicKey = "-----BEGIN PUBLIC KEY-----\n"
                            + n + "\n"
                            + e + "\n"
                            + "-----END PUBLIC KEY-----";

                    wellKnownKeys.add(publicKey);
                }
            }
        }

        return wellKnownKeys;
    }

    private RSAPublicKey getPublicKey(List<String> wellKnownKeys) {
        try {
            for (String publicKeyString : wellKnownKeys) {
                byte[] decodedKey = Base64.getDecoder().decode(publicKeyString);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(keySpec);

                if (publicKey instanceof RSAPublicKey) {
                    return (RSAPublicKey) publicKey;
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
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

    @Scheduled(cron = "0 0 * * * *")
    public void evictCache() {
        cacheManager.getCache("wellKnownKeysCache").clear();
    }

}
