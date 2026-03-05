package com.jwt.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.jwt.auth.entity.RefreshToken;
import com.jwt.auth.entity.User;
import com.jwt.auth.exception.NotFoundException;
import com.jwt.auth.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;
    public RefreshToken createRefreshToken(User user){
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60)); 
        token.setRevoked(false);

        return refreshTokenRepository.save(token);
        
    }
    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.isRevoked())
            throw new RuntimeException("Token revoked");

        if (refreshToken.getExpiryDate().isBefore(Instant.now()))
            throw new RuntimeException("Token expired");

        return refreshToken;
    }

    public void revokeToken(String token) {
        RefreshToken refreshToken = verifyRefreshToken(token);
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
    }
    public RefreshToken rotateRefreshToken(RefreshToken oldToken){
        refreshTokenRepository.delete(oldToken);
        return createRefreshToken(oldToken.getUser());

    }
    public void logout(String token){
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
        .orElseThrow(() -> new NotFoundException("Refresh token not found"));
        refreshTokenRepository.delete(refreshToken);
    }
	
}
