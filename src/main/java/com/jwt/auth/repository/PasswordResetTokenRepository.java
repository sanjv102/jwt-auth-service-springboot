package com.jwt.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.auth.entity.PasswordResetToken;
import com.jwt.auth.entity.User;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long>{

	 Optional<PasswordResetToken> findByToken(String token);
	    void deleteByUser(User user);
	
}
