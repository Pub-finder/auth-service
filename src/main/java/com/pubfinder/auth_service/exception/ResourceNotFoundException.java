package com.pubfinder.auth_service.exception;

import java.io.Serial;

public class ResourceNotFoundException extends Exception {

  @Serial
  private static final long serialVersionUID = 1L;

  public ResourceNotFoundException(String message) {
    super(message);
  }

  public ResourceNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }
}
