package com.akshayedusource.vaultIntergration.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionControl {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception ex) {
        ProblemDetail errorDetail = null;

        if (ex instanceof JWTVerificationException) {
            errorDetail = ProblemDetail
                    .forStatusAndDetail(HttpStatusCode.valueOf(403), ex.getMessage());
            errorDetail.setProperty("access_denied_reason", "JWT Signature not valid");
        }
        if (ex instanceof ExpiredJwtException) {
            errorDetail = ProblemDetail
                    .forStatusAndDetail(HttpStatusCode.valueOf(403), ex.getMessage());
            errorDetail.setProperty("access_denied_reason", "JWT Token already expired !");
        }
        else if(ex instanceof Exception){
            errorDetail = ProblemDetail
                    .forStatusAndDetail(HttpStatusCode.valueOf(500), ex.getMessage());
            errorDetail.setProperty("exception", "Exception in application please contact support");
        }

        return errorDetail;
    }
}
