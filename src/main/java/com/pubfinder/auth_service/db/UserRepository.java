package com.pubfinder.auth_service.db;


import com.pubfinder.auth_service.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

  Optional<User> findByEmail(String email);

  Optional<User> findByUsername(String username);
}