package com.akshayedusource.vaultIntergration.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/rest")
public class HelloController {

    @GetMapping("/hello")
    @PreAuthorize("hasRole('kafka_admin')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<String> hello() {
        return new ResponseEntity<String>("Hello", HttpStatus.ACCEPTED);
    }
}