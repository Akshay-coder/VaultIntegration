package com.akshayedusource.vaultIntergration.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
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
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Data
public class JwtValidationService {

    @Value("${jwt.issuer}")
    private String expectedIssuer;

    @Value("${jwt.namespace}")
    private String expectedNamespace;

//    @Autowired
//    private CacheManager cacheManager;

    @Autowired
    RestTemplate restTemplate;

    public static final String WELL_KNOWN_KEYS_ENDPOINT="/.well-known/keys";

    public boolean validateJwtToken(String jwtToken) {
        try {
            DecodedJWT decodedJWT = JWT.decode(jwtToken);
            String issuer = decodedJWT.getIssuer();

            List<Map<String, String>> wellKnownKeys = getWellKnownKeysFromIssuer(issuer);

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
    private List<Map<String, String>> getWellKnownKeysFromIssuer(String issuer) {
        String wellKnownKeysUrl = issuer + WELL_KNOWN_KEYS_ENDPOINT;
        ResponseEntity<Map> responseEntity;
//        responseEntity = restTemplate.getForEntity(wellKnownKeysUrl, Map.class);
        List<String> wellKnownKeys = new ArrayList<>();

//        Map<String, Object> responseBody =
//        if (responseBody != null) {
        List<Map<String, String>> keys = new ArrayList<>();

        Map<String, String> key1 = new HashMap<>();
        key1.put("use", "sig");
        key1.put("kty", "RSA");
        key1.put("kid", "00570099-d5ef-5d29-123f-faf28522a8ec");
        key1.put("alg", "RS256");
        key1.put("n", "xlcmNzEiGX1huyXC-x4wmPIXiDo2paGLGCMIQKB8nQvFU-JElAFQkFzMFEgQkPlq0X0ObeOxtBQlJEXlthsRt-6MUjumud-uG2cQcz8WUGD08G32xIMOILV5DK9UrsPOrJKW_MumAXlMviyBcQu3Ft1qQEDaLxR4m_bVW5pJnNIhicuTm9-wLyjaKSNxJty8ReOYh0OI-a5gQ33G39XoILpMo-DcuC6CP-ME-T4YFK7favGpUYXDsAaN8wbGWarAx56XkiAWPx2PhIMRt8DGLvCR-L91gTE2yKKx9ABLAxRVew5xxdeGZgWCUAZo-T7-vcIlCi3nGW4n3DWdtnK6aw");
        key1.put("e", "AQAB");

        Map<String, String> key2 = new HashMap<>();
        key2.put("use", "sig");
        key2.put("kty", "RSA");
        key2.put("kid", "aa4e6f6b-15d7-89a9-24cc-907155113f77");
        key2.put("alg", "RS256");
        key2.put("n", "quE05txf4gj8AcG1VhySEzpk7T4JkFOzWRpqDnZgy7Jv9zs5h7dqWVLkG-vV7yINrO5o5Qrr7A9XdIU62LvHGQvLjDWykAFfBWr1GDuyq0vqHpCcW97B2RFRFouKVQ1PmgfgAW172r2sHcNXEbwK8RK1saPQfODynwy0qet9cPlrW_wAIhYME2cldfy0PZY8Q9GImvsMjYnSORfOCwBNNqT-kwcVZgO7IscYrmWlPZrGdKsypSXE70EbOxPoQJjTqeP9oevNKg6Pnd1yya2hy-8sGsipNFWqfbOzaDgBttoVyFcNyp1GDMC-gmJmo0vPEYBGA5IsxHZ8CMF1Ixg33w");
        key2.put("e", "AQAB");

        Map<String, String> key3 = new HashMap<>();
        key3.put("use", "sig");
        key3.put("kty", "RSA");
        key3.put("kid", "f81acfea-dfae-b3d6-a895-bff4dfc1b4ad");
        key3.put("alg", "RS256");
        key3.put("n", "4Q4e7WccWtKm77ngU7tatiV-uE5AMbBvIqtb-QcFc_J97v68Z0jyk0ezyh6BV7UAVmL_BAuTQrZdaEJIUaMFNDqproyMqmRN3E2n_68oXodttKCZDS7q3dMZ0WAs-DT-aKkNubGcbpQC17xvrvyoMUS3Ub57HLWs9dV-XfKBem6ouGTI-IaDP75XM82CNzG8Hv1jwC3G4RpuWDE-AmK9zWFrToay3YL5j3Mcbc1bqeNi4sYVZQ_C7CgN-vR8UdE1i4vpbgaQ1mRsfc7Q0BAAYxCPa0pSlGROc3XRUjtc5LW_dlIh16Uwx3PzrsR8I0tp3BInJyrGO2sYOfgvbXHHrQ");
        key3.put("e", "AQAB");

        keys.add(key1);
        keys.add(key2);
        keys.add(key3);

        return keys;
    }

//    private RSAPublicKey getPublicKey(List<String> wellKnownKeys) {
//        try {
//            for (String publicKeyString : wellKnownKeys) {
//                String base64EncodedKey = publicKeyString
//                        .replace("-----BEGIN PUBLIC KEY-----", "")
//                        .replace("-----END PUBLIC KEY-----", "")
//                        .replaceAll("\\s+", "");
//                byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKey);
//                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
//                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//                PublicKey publicKey = keyFactory.generatePublic(keySpec);
//
//                if (publicKey instanceof RSAPublicKey) {
//                    return (RSAPublicKey) publicKey;
//                }
//            }
//        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//        return null;
//    }

    private RSAPublicKey getPublicKey(List<Map<String, String>> wellKnownKeys) {
        try {
            for (Map<String, String> key : wellKnownKeys) {
                String kty = key.get("kty");
                String modulus = key.get("n");
                String exponent = key.get("e");

                if ("RSA".equals(kty)) {
                    byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
                    byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);

                    BigInteger modulusInt = new BigInteger(1, modulusBytes);
                    BigInteger exponentInt = new BigInteger(1, exponentBytes);

                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusInt, exponentInt);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(keySpec);

                    if (publicKey instanceof RSAPublicKey) {
                        return (RSAPublicKey) publicKey;
                    }
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
            return signedJWT.getJWTClaimsSet().getStringListClaim("groups").stream().map(s -> "ROLE_" + s).collect(Collectors.toList());
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }

    }

//    @Scheduled(cron = "0 0 * * * *")
//    public void evictCache() {
//        cacheManager.getCache("wellKnownKeysCache").clear();
//    }
}
