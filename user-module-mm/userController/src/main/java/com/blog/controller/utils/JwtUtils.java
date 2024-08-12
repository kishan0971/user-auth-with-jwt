package com.blog.controller.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//* The JwtUtils class provides utility methods for generating, extracting, and validating JSON Web Tokens (JWTs) using a secret key.
@Component
public class JwtUtils {
    private String SECRET_KEY = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V";
    private String REFRESH_SECRET_KEY =  "AnotherSecretKeyForRefreshTokens";

    //* Gets the secret key used for signing the tokens.
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    //* Generates a JWT for the given username.
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }
    //* Creates a JWT with specified claims and subject (username). It includes an issued date, expiration time, and is signed with the secret key.
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .header().empty().add("typ","JWT")
                .and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 50)) // 5 minutes expiration time
                .signWith(getSigningKey())
                .compact();
    }

    //* Extracts the username (subject) from the given token.
    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }

    //* Extracts all claims from the given token.
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    //* Validates the token by checking its expiration.
    public Boolean validateToken(String token) {
        return !isTokenExpired(token);
    }

    //* Checks if the token is expired.
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    //* Extracts the expiration date from the token.
    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }
}
