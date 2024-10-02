package com.pubfinder.auth_service.util;

import com.pubfinder.auth_service.dto.AuthenticationResponse;
import com.pubfinder.auth_service.models.Token;
import com.pubfinder.auth_service.models.User;
import com.pubfinder.auth_service.models.enums.Role;
import com.pubfinder.auth_service.models.enums.TokenType;

import java.util.UUID;

public class TestUtil {

    public static User generateMockUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("username")
                .password("password")
                .role(Role.USER)
                .build();
    }

    public static Token generateMockToken(User user) {
        return Token.builder()
                .token("xxxxx.yyyyy.zzzzz")
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .user(user)
                .build();
    }

    public static AuthenticationResponse generateMockAuthenticationResponse(String accessToken, String refreshToken) {
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
