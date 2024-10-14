package com.pubfinder.auth_service.exception;

import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(value = ResourceNotFoundException.class)
  public ResponseEntity<String> handleResourceNotFoundException(ResourceNotFoundException ex) {
    // Log exception Message
    return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(value = BadRequestException.class)
  public ResponseEntity<String> handleBadRequestException(BadRequestException ex) {
    // Log exception Message
    return new ResponseEntity<>("Bad Request", HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(value = BadCredentialsException.class)
  public ResponseEntity<String> handleBadCredentialsException(BadCredentialsException ex) {
    return new ResponseEntity<>("Bad Credentials", HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(value = AccessDeniedException.class)
  public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
    // Log exception Message
    return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(value = InvalidPasswordException.class)
  public ResponseEntity<String> handleInvalidPasswordException(InvalidPasswordException ex) {
    // Log exception Message
    return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
  }
}
