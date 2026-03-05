package com.jwt.auth.service;

import com.jwt.auth.dto.AuthResponse;
import com.jwt.auth.dto.LoginRequest;
import com.jwt.auth.dto.RegisterRequest;

public interface AuthService {

	void register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
    void logout(String refreshToken);
	
}
