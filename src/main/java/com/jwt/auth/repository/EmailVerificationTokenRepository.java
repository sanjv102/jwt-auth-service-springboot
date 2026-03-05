package com.jwt.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.auth.entity.EmailVerificationToken;
import com.jwt.auth.entity.User;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long>{

	Optional<EmailVerificationToken> findByToken(String Long);
    void deleteByUser(User user);
	
}
