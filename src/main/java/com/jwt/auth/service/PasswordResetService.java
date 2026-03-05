package com.jwt.auth.service;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.auth.entity.PasswordResetToken;
import com.jwt.auth.entity.User;
import com.jwt.auth.exception.BadRequestException;
import com.jwt.auth.exception.NotFoundException;
import com.jwt.auth.repository.PasswordResetTokenRepository;
import com.jwt.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

	private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    public void createResetToken(String email){
        User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new NotFoundException("User not found"));
        tokenRepository.deleteByUser(user);
        PasswordResetToken token = new PasswordResetToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryTime(LocalDateTime.now().plusMinutes(15));
        tokenRepository.save(token);
        System.out.println("PASSWORD RESET TOKEN: " + token.getToken());
    }
    public void resetPassword(String tokenValue, String newPassword){
        PasswordResetToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new BadRequestException("Invalid reset token"));
        if(token.getExpiryTime().isBefore(LocalDateTime.now())){
            throw new BadRequestException("Reset token expired");
        }
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        tokenRepository.delete(token);
    }
	
}
