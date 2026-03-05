package com.jwt.auth.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.auth.audit.AuditEventType;
import com.jwt.auth.entity.User;
import com.jwt.auth.exception.NotFoundException;
import com.jwt.auth.repository.UserRepository;
import com.jwt.auth.response.ApiResponse;
import com.jwt.auth.service.AuditLogService;
import com.jwt.auth.util.RequestContext;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;

@SecurityRequirement(name="BearerAuth")
@RestController
@RequestMapping("api/user")
@RequiredArgsConstructor
public class UserController {

	private final UserRepository userRepository;
	private final AuditLogService auditLogService;
	
	@GetMapping("/dashboard")
	@PreAuthorize("hasRole('USER')")
	public ApiResponse<?> userDashboard(){
		auditLogService.log(
				AuditEventType.ACCESS_USER_DASHBOARD, 
				SecurityContextHolder.getContext().getAuthentication().getName(), 
				RequestContext.getIp(), 
				"/api/user/dashboard", 
				true
			);
		return new ApiResponse<>(
			true,
			"Welcome USER! This is your dashboard.",
			null
		);
	}
	
	@GetMapping("/me")
	@PreAuthorize("hasRole('USER')")
	public ApiResponse<?> me(){
		String email = SecurityContextHolder.getContext().getAuthentication().getName();
		User user = userRepository.findByEmail(email).orElseThrow(()-> new NotFoundException("User Not Found"));
		
		auditLogService.log(
				AuditEventType.TOKEN_ACCESS, 
				email, 
				RequestContext.getIp(), 
				"/api/user/me", 
				true
			);
		return new ApiResponse<>(
				true,
				"Authenticated User Details",
				Map.of(
						"email", user.getEmail(),
						"roles", user.getRoles(),
						"enabled", user.isEnabled()
						)
				);
	}
	
}
