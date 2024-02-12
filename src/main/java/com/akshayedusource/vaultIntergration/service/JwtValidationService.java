package com.akshayedusource.vaultIntergration.service;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;

@Service
public class JwtValidationService {

    @Autowired
    private final RestTemplate restTemplate;

    public JwtValidationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean validateJwtToken(String jwtToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();

            JWKSet jwkSet = JWKSet.load(new URL(issuer));

            String kid = signedJWT.getHeader().getKeyID();

            JWK jwk = jwkSet.getKeyByKeyId(kid);

            if (jwk instanceof RSAKey) {
                RSAPublicKey publicKey = ((RSAKey) jwk).toRSAPublicKey();
                return signedJWT.verify(new RSASSAVerifier(publicKey));
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
