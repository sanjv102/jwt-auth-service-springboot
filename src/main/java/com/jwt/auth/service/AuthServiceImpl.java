package com.jwt.auth.service;

import java.time.LocalDateTime;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.auth.audit.AuditEventType;
import com.jwt.auth.dto.AuthResponse;
import com.jwt.auth.dto.LoginRequest;
import com.jwt.auth.dto.RegisterRequest;
import com.jwt.auth.entity.RefreshToken;
import com.jwt.auth.entity.Role;
import com.jwt.auth.entity.User;
import com.jwt.auth.exception.BadRequestException;
import com.jwt.auth.exception.NotFoundException;
import com.jwt.auth.exception.UnauthorizedException;
import com.jwt.auth.repository.RoleRepository;
import com.jwt.auth.repository.UserRepository;
import com.jwt.auth.util.JwtService;
import com.jwt.auth.util.RequestContext;
import com.jwt.auth.util.SecurityConstants;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService; 
	private final EmailVerificationService emailVerificationService;
	private final AuditLogService auditLogService;
	
	
	
	@Override
	public void register(RegisterRequest request) {
		
		if(userRepository.existsByEmail(request.getEmail())) {
			throw new BadRequestException("Email already registered.");
		}
		
		Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow(()->new NotFoundException("ROLE_USER not found in DB."));
		User user = new User();
			user.setName(request.getName());
			user.setEmail(request.getEmail());
			user.setPassword(request.getPassword());
			user.setRoles(Set.of(userRole));
			user.setEnabled(false);
			userRepository.save(user);
			
			emailVerificationService.createVerificationToken(user);
	}

	@Override
	public AuthResponse login(LoginRequest request) {
		User user = userRepository.findByEmail(request.getEmail()).orElseThrow(()->new NotFoundException("User Not Found"));
		
		if(!user.isEnabled()) {
			auditLogService.log(
					AuditEventType.LOGIN_BLOCKED,
					user.getEmail(),
					RequestContext.getIp(),
					"/api/auth/login",
					false
				);
			throw new UnauthorizedException("Account No Verified");
		}
		
		if (isAccountLocked(user)) {
	        auditLogService.log(
	            AuditEventType.LOGIN_BLOCKED,
	            user.getEmail(),
	            RequestContext.getIp(),
	            "/api/auth/login",
	            false
	        );
	        throw new UnauthorizedException("Account is locked. Try again later");
	    }

	    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
	        increaseFailedAttempts(user);
	        auditLogService.log(
	            AuditEventType.LOGIN_FAILED,
	            user.getEmail(),
	            RequestContext.getIp(),
	            "/api/auth/login",
	            false
	        );
	        throw new UnauthorizedException("Invalid credentials");
	    }

	    resetFailedAttempts(user);

	    String accessToken = jwtService.generateToken(user.getEmail());
	    RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

	    auditLogService.log(
	        AuditEventType.LOGIN_SUCCESS,
	        user.getEmail(),
	        RequestContext.getIp(),
	        "/api/auth/login",
	        true
	    );

	    return new AuthResponse(accessToken, refreshToken.getToken());
	}

	@Override
	public void logout(String refreshToken) {
		refreshTokenService.logout(refreshToken);
		auditLogService.log(
				AuditEventType.LOGOUT,
		        null,
		        RequestContext.getIp(),
		        "api/auth/logout",
		        true
			);
	}
	
	private boolean isAccountLocked(User user){
	    if(user.getLockTime() == null) return false;
	    return user.getLockTime()
	             .plus(SecurityConstants.LOCK_TIME_DURATION)
	             .isAfter(LocalDateTime.now());
	   }
	
	private void lockAccount(User user) {
		user.setLockTime(LocalDateTime.now());
		userRepository.save(user);
	}
	
	private void resetFailedAttempts(User user) {
	    user.setFailedAttempts(0);
	    user.setLockTime(null);
	    userRepository.save(user);
	   }

	   private void increaseFailedAttempts(User user) {
	    int attempts = user.getFailedAttempts() + 1;
	    user.setFailedAttempts(attempts);

	    if (attempts >= SecurityConstants.MAX_FAILED_ATTEMPTS) {
	        user.setLockTime(LocalDateTime.now());
	        auditLogService.log(
	            AuditEventType.ACCOUNT_LOCKED,
	            user.getEmail(),
	            RequestContext.getIp(),
	            "/api/auth/login",
	            false

	        );
	    }

	    userRepository.saveAndFlush(user); 
	}
}
