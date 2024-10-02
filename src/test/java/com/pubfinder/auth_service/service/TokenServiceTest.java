package com.pubfinder.auth_service.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

@SpringBootTest(properties = {
        "spring.datasource.url=",
        "spring.jpa.database-platform=",
        "spring.jpa.hibernate.ddl-auto=none",
        "security.jwt-expiration-ms=6000"
})
public class TokenServiceTest {

    @Autowired
    private TokenService tokenService;

    @Test
    public void generateAccessTokenAndValidateTest() {
        UUID userId = UUID.randomUUID();
        String token = tokenService.generateToken(userId);
        Assertions.assertTrue(tokenService.isTokenValid(token, userId));
    }


    @Test
    public void generateRefreshTokenAndValidateTest() {
        UUID userId = UUID.randomUUID();
        String token = tokenService.generateRefresherToken(userId);
        Assertions.assertTrue(tokenService.isTokenValid(token, userId));
    }

    @Test
    public void validateInvalidTokenTest() {
        String token = tokenService.generateToken(UUID.randomUUID());
        Assertions.assertFalse(tokenService.isTokenValid(token, UUID.randomUUID()));
    }

    @Test
    public void validateInvalidTokenTest_TimesPassed() throws InterruptedException {
        UUID userId = UUID.randomUUID();
        String token = tokenService.generateToken(userId);
        Thread.sleep(6000);
        Assertions.assertFalse(tokenService.isTokenValid(token, userId));
    }

    @Test
    public void extractUserIdTest() {
        UUID userId = UUID.randomUUID();
        String token = tokenService.generateToken(userId);
        String id = tokenService.extractUserId(token);

        Assertions.assertEquals(userId, UUID.fromString(id));
    }
}
