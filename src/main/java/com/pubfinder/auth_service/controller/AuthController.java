package com.pubfinder.auth_service.controller;

import com.pubfinder.auth_service.dto.AuthenticationResponse;
import com.pubfinder.auth_service.dto.LoginRequest;
import com.pubfinder.auth_service.dto.TokenValidationResponse;
import com.pubfinder.auth_service.exception.ResourceNotFoundException;
import com.pubfinder.auth_service.service.AuthService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;


/**
 * The type Authorization controller.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

  @Autowired
  private AuthService authService;

  @GetMapping(value = "/validateToken/{token}")
  public ResponseEntity<TokenValidationResponse> validateToken(@PathVariable("token") String token) throws ResourceNotFoundException {
    return ResponseEntity.ok(authService.validateToken(token));
  }

  @GetMapping("/refreshToken/{token}")
  public ResponseEntity<AuthenticationResponse> refreshToken(@PathVariable("token") String token) throws BadRequestException, ResourceNotFoundException {
    return ResponseEntity.ok(authService.refreshToken(token));
  }

  @PostMapping("/login")
  public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest loginRequest) throws ResourceNotFoundException {
    return ResponseEntity.ok(authService.login(loginRequest));
  }

  @DeleteMapping("/logout/{token}")
  public ResponseEntity<Void> logout(@PathVariable("token") String token) throws ResourceNotFoundException {
    authService.logout(token);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/generateToken/{userId}")
  public ResponseEntity<AuthenticationResponse> generateToken(@PathVariable("userId") UUID userId) throws ResourceNotFoundException {
    return ResponseEntity.status(HttpStatus.CREATED)
            .body(authService.generateToken(userId));
  }
}
