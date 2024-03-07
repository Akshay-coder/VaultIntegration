package com.akshayedusource.vaultIntergration.config;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class ExcludedURLs {

    public static List<Pattern> getPatterns() {
        List<Pattern> excludedPatterns = new ArrayList<>();

        // Add regular expressions representing URLs to be excluded
        excludedPatterns.add(Pattern.compile(".*/swagger-ui/.*")); // Exclude Swagger UI
        excludedPatterns.add(Pattern.compile(".*/v3/api-docs/.*")); // Exclude Swagger API documentation
        excludedPatterns.add(Pattern.compile(".*/actuator/.*")); // Exclude Actuator endpoints

        return excludedPatterns;
    }
}
