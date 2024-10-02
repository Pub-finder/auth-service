package com.pubfinder.auth_service.service;

import com.pubfinder.auth_service.db.TokenRepository;
import com.pubfinder.auth_service.db.UserRepository;
import com.pubfinder.auth_service.dto.AuthenticationResponse;
import com.pubfinder.auth_service.dto.LoginRequest;
import com.pubfinder.auth_service.exception.InvalidPasswordException;
import com.pubfinder.auth_service.exception.ResourceNotFoundException;
import com.pubfinder.auth_service.models.Token;
import com.pubfinder.auth_service.models.User;
import com.pubfinder.auth_service.util.TestUtil;
import org.apache.coyote.BadRequestException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(properties = {
        "spring.datasource.url=",
        "spring.jpa.database-platform=",
        "spring.jpa.hibernate.ddl-auto=none"
})
public class AuthServiceTest {
    @Autowired
    private AuthService authService;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private TokenRepository tokenRepository;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @Test
    public void validateTokenTest_ValidToken() throws ResourceNotFoundException {
        Token token = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(token.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.isTokenValid(token.getToken(), user.getId())).thenReturn(Boolean.TRUE);

        Boolean result = authService.validateToken(token.getToken());

        assertTrue(result);
        verify(userRepository, times(1)).findById(user.getId());
    }

    @Test
    public void validateTokenTest_InvalidToken() throws ResourceNotFoundException {
        Token token = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(token.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.isTokenValid(token.getToken(), user.getId())).thenReturn(Boolean.FALSE);

        Boolean result = authService.validateToken(token.getToken());

        assertFalse(result);
        verify(userRepository, times(1)).findById(user.getId());
    }

    @Test
    public void validateTokenTest_ResourceNotFoundException() {
        Token token = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(token.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authService.validateToken(token.getToken()));
        verify(userRepository, times(1)).findById(user.getId());
    }

    @Test
    public void validateTokenTest_ResourceNotFoundException_InvalidUUID() {
        Token token = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(token.getToken())).thenReturn("1234");
        assertThrows(ResourceNotFoundException.class, () -> authService.validateToken(token.getToken()));
    }

    @Test
    public void refreshTokenTest() throws BadRequestException, ResourceNotFoundException {
        Token refreshToken = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(refreshToken.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.isTokenValid(refreshToken.getToken(), user.getId())).thenReturn(Boolean.TRUE);
        when(tokenService.generateToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");
        when(tokenService.generateRefresherToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");
        when(tokenRepository.findAllTokensByUser(user.getId())).thenReturn(List.of());

        AuthenticationResponse response = authService.refreshToken(refreshToken.getToken());

        assertFalse(response.getRefreshToken().isEmpty());
        assertFalse(response.getAccessToken().isEmpty());
    }

    @Test
    public void refreshTokenTest_BadRequestException() throws BadRequestException, ResourceNotFoundException {
        assertThrows(BadRequestException.class, () -> authService.refreshToken(null));
    }

    @Test
    public void refreshTokenTest_UserIdNotFound() {
        Token refreshToken = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(refreshToken.getToken())).thenReturn(null);
        assertThrows(ResourceNotFoundException.class, () -> authService.refreshToken(refreshToken.getToken()));
    }

    @Test
    public void refreshTokenTest_UserNotFound() {
        Token refreshToken = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(refreshToken.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authService.refreshToken(refreshToken.getToken()));
    }

    @Test
    public void refreshTokenTest_InvalidToken() {
        Token refreshToken = TestUtil.generateMockToken(user);

        when(tokenService.extractUserId(refreshToken.getToken())).thenReturn(user.getId().toString());
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.isTokenValid(refreshToken.getToken(), user.getId())).thenReturn(Boolean.FALSE);

        assertThrows(BadCredentialsException.class, () -> authService.refreshToken(refreshToken.getToken()));
    }

    @Test
    public void loginTest() throws ResourceNotFoundException {
        when(userRepository.findByUsername(user.getUsername())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(any(), any())).thenReturn(Boolean.TRUE);
        when(tokenService.generateToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");
        when(tokenService.generateRefresherToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");
        when(tokenRepository.findAllTokensByUser(user.getId())).thenReturn(List.of());


        LoginRequest loginRequest = LoginRequest.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .build();

        AuthenticationResponse response = authService.login(loginRequest);

        assertFalse(response.getRefreshToken().isEmpty());
        assertFalse(response.getAccessToken().isEmpty());
    }

    @Test
    public void loginTest_ResourceNotFoundException() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .build();

        when(userRepository.findByUsername(user.getUsername())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authService.login(loginRequest));
    }

    @Test
    public void loginTest_InvalidPasswordException() {
        LoginRequest loginRequest = LoginRequest.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .build();

        when(userRepository.findByUsername(user.getUsername())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(any(), any())).thenReturn(Boolean.FALSE);
        assertThrows(InvalidPasswordException.class, () -> authService.login(loginRequest));
    }

    @Test
    public void generateTokenTest() throws ResourceNotFoundException {

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.generateToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");
        when(tokenService.generateRefresherToken(user.getId())).thenReturn("xxxxx.yyyyy.zzzzz");

        AuthenticationResponse response = authService.generateToken(user.getId());
        assertFalse(response.getRefreshToken().isEmpty());
        assertFalse(response.getAccessToken().isEmpty());
    }

    @Test
    public void generateTokenTest_ResourceNotFoundException() throws ResourceNotFoundException {
        when(userRepository.findById(user.getId())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authService.generateToken(user.getId()));
    }

    private final User user = TestUtil.generateMockUser();
}
