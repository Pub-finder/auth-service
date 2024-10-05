package com.pubfinder.auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * The type Token service.
 */
@Component
public class TokenService {

    @Value("${security.jwt-secret}")
    private String SECRET_KEY;
    @Value("${security.jwt-expiration-ms}")
    private long JWT_EXPIRATION;
    @Value("${security.jwt-refresh-expiration-ms}")
    private long REFRESHER_EXPIRATION;

    public String extractUserId(String jwt) {
        try {
            return extractClaim(jwt, Claims::getSubject);
        } catch (ExpiredJwtException | MalformedJwtException | SignatureException e) {
            return null;
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generate access token string.
     *
     * @param userId the users id
     * @return the string
     */
    public String generateToken(UUID userId) {
        return buildToken(new HashMap<>(), userId, JWT_EXPIRATION);
    }

    /**
     * Generate refresher token string.
     *
     * @param userId the users id
     * @return the string
     */
    public String generateRefresherToken(UUID userId) {
        return buildToken(new HashMap<>(), userId, REFRESHER_EXPIRATION);
    }

    /**
     * Build token string.
     *
     * @param extractClaims the extracted claims
     * @param id            the user id
     * @param exertionTime  the exertion time
     * @return the string
     */
    public String buildToken(Map<String, Object> extractClaims, UUID id,
                             long exertionTime) {
        return Jwts
                .builder()
                .claims(extractClaims)
                .subject(id.toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + exertionTime))
                .signWith(getSignInKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UUID userId) {
        try {
            final String id = extractUserId(token);
            return userId.toString().equals(id) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}