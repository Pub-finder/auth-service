package com.pubfinder.auth_service.service;

import com.pubfinder.auth_service.db.TokenRepository;
import com.pubfinder.auth_service.db.UserRepository;
import com.pubfinder.auth_service.dto.AuthenticationResponse;
import com.pubfinder.auth_service.dto.LoginRequest;
import com.pubfinder.auth_service.dto.TokenValidationResponse;
import com.pubfinder.auth_service.exception.InvalidPasswordException;
import com.pubfinder.auth_service.exception.ResourceNotFoundException;
import com.pubfinder.auth_service.models.Token;
import com.pubfinder.auth_service.models.User;
import com.pubfinder.auth_service.models.enums.Role;
import com.pubfinder.auth_service.models.enums.TokenType;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;


/**
 * The type Authentication filter.
 */
@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenService tokenService;

    /**
     * Validate access token.
     *
     * @param jwt the access token
     * @return if the token is valid
     * @throws ResourceNotFoundException the user not found or the id in the token is invalid UUID exception
     */
    public TokenValidationResponse validateToken(String jwt, UUID userId)
            throws ResourceNotFoundException {
        try {
            String id = tokenService.extractUserId(jwt);
            if (id == null) {
                return TokenValidationResponse.INVALID;
            }

            UUID tokenUserId = UUID.fromString(id);
            User tokenUser = userRepository.findById(tokenUserId).orElseThrow(() -> new ResourceNotFoundException(
                    "User with id: " + tokenUserId + " was not found")
            );

            if (!tokenService.isIdValid(jwt, tokenUserId) || (tokenUser.getId() != userId && !tokenUser.getRole().equals(Role.ADMIN)))
                return TokenValidationResponse.INVALID;

            return TokenValidationResponse.VALID;
        } catch (ExpiredJwtException e) {
            return TokenValidationResponse.EXPIRED;
        } catch (MalformedJwtException | SignatureException | IllegalArgumentException e) {
            return TokenValidationResponse.INVALID;
        }
    }

    /**
     * Refresh users access token.
     *
     * @param refreshToken the refresh token
     * @return the authentication response
     * @throws BadRequestException       the authHeader was empty exception
     * @throws ResourceNotFoundException the user or refreshToken not found exception
     */
    public AuthenticationResponse refreshToken(String refreshToken)
            throws BadRequestException, ResourceNotFoundException {

        if (refreshToken == null) {
            throw new BadRequestException();
        }

        String userId = Optional.ofNullable(tokenService.extractUserId(refreshToken))
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User with refresherToken: " + refreshToken + " was not found"));
        UUID id = UUID.fromString(userId);

        User user = userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException(
                        "User with id: " + id + " was not found"));

        if (!tokenService.isTokenValid(refreshToken, id)) {
            throw new BadCredentialsException("Token was invalid");
        }

        String newAccessToken = tokenService.generateToken(id);
        String newRefreshToken = tokenService.generateRefresherToken(id);

        deleteAllUserTokens(id);
        saveToken(user, newAccessToken);

        return AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    /**
     * Login user, and return the access- and refresher-token.
     *
     * @param loginRequest the login request
     * @return the authentication response
     * @throws ResourceNotFoundException the user not found exception
     */
    public AuthenticationResponse login(LoginRequest loginRequest) throws ResourceNotFoundException {
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(
                () -> new ResourceNotFoundException(
                        "User with username: " + loginRequest.getUsername() + " not found"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new InvalidPasswordException("Incorrect password");
        }

        var accessToken = tokenService.generateToken(user.getId());
        var refreshToken = tokenService.generateRefresherToken(user.getId());

        deleteAllUserTokens(user.getId());
        saveToken(user, accessToken);

        return AuthenticationResponse.builder()
                .userId(user.getId())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse generateToken(UUID userId) throws ResourceNotFoundException {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new ResourceNotFoundException(
                        "User with id: " + userId + " not found"));

        var accessToken = tokenService.generateToken(userId);
        var refreshToken = tokenService.generateRefresherToken(userId);

        saveToken(user, accessToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    private void deleteAllUserTokens(UUID id) {
        List<Token> tokens = tokenRepository.findAllTokensByUser(id);
        tokens.forEach((token -> tokenRepository.delete(token)));
    }

    private void saveToken(User user, String accessToken) {
        Token token = Token.builder()
                .token(accessToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .user(user)
                .build();

        tokenRepository.save(token);
    }

    public void logout(String token) throws ResourceNotFoundException {
        Token storedToken = tokenRepository.findByToken(token).orElseThrow(() -> new ResourceNotFoundException(
                "Token : " + token + " not found"));
        tokenRepository.delete(storedToken);
    }
}