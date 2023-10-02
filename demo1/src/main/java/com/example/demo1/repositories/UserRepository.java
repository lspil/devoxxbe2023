package com.example.demo1.repositories;

import com.example.demo1.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

  @Query("""
    SELECT u FROM User u WHERE u.username = :username
  """)
  Optional<User> findByUsername(String username);
}
