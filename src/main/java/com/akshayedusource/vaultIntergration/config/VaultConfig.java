package com.akshayedusource.vaultIntergration.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

import java.net.URI;

@Configuration
public class VaultConfig {

    @Value("${vault.token}")
    private String vaultToken;

    @Value("${vault.url}")
    private String vaultUrl;

    @Bean
    public VaultTemplate vaultTemplate() {
        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(vaultUrl));
        TokenAuthentication authentication = new TokenAuthentication(vaultToken);
        VaultTemplate vaultTemplate = new VaultTemplate(endpoint, authentication);
        return vaultTemplate;
    }
}