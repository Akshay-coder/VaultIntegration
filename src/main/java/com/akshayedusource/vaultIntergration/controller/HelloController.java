package com.akshayedusource.vaultIntergration.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/rest")
public class HelloController {

    @GetMapping("/hello")
    @SecurityRequirement(name = "Bearer Authentication")
    public String hello() {
        return "Hello, World!";
    }
}