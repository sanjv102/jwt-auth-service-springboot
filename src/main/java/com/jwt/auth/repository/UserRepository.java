package com.jwt.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.auth.entity.User;

public interface UserRepository extends JpaRepository<User, Long>{

	Optional<User> findByEmail(String email);
	Boolean existsByEmail(String email);
}
