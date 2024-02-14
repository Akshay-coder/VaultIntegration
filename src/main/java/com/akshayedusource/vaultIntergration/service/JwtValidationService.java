package com.akshayedusource.vaultIntergration.service;

import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Data
public class JwtValidationService {

    @Value("${jwt.issuer}")
    private String expectedIssuer;

    @Value("${jwt.namespace}")
    private String expectedNamespace;

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
}
