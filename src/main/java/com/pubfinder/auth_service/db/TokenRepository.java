package com.pubfinder.auth_service.db;

import com.pubfinder.auth_service.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, UUID> {

  Optional<Token> findByToken(String token);

  @Query("SELECT t FROM Token t INNER JOIN User u "
      + "ON t.user.id = u.id "
      + "where u.id = :id")
  List<Token> findAllTokensByUser(UUID id);
}
