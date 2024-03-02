package com.akshayedusource.vaultIntergration.config;

import com.akshayedusource.vaultIntergration.exceptions.TokenExpiredException;
import com.akshayedusource.vaultIntergration.service.JwtValidationService;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@Slf4j
public class AuthFilter extends OncePerRequestFilter {

    @Autowired
    JwtValidationService jwtAuthService;

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private HandlerExceptionResolver handlerExceptionResolver;

    @Autowired
    public AuthFilter(HandlerExceptionResolver exceptionResolver) {
        this.handlerExceptionResolver = exceptionResolver;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new RuntimeException("Authorization header not found or not in Bearer format.");
            }

            token = authHeader.substring(7);
            log.debug("Received JWT token: {}", token);


            if (jwtAuthService.validateJwtToken(token)) {
                log.debug("JWT token validation successful.");

                List<String> groups = jwtAuthService.getClaims(token);
                if (groups != null && !groups.isEmpty()) {
                    log.debug("Extracted claims from JWT token: {}", groups);

                    List<SimpleGrantedAuthority> authorities = groups.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(null, null, authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    log.debug("User authenticated successfully with authorities: {}", authorities);
                } else {
                    log.warn("No claims found in JWT token.");
                }
            } else {
                log.warn("JWT token validation failed.");
                throw new JWTVerificationException("JWT token validation failed.");

            }
        } catch (JWTVerificationException | TokenExpiredException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, e);
        } catch (Exception e) {
            log.error("Error occurred during JWT token validation: {}", e.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
        filterChain.doFilter(request,response);
    }


}
