package com.jwt.auth.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.jwt.auth.audit.AuditEventType;
import com.jwt.auth.audit.AuditLog;
import com.jwt.auth.repository.AuditLogRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuditLogService {

	private final AuditLogRepository auditLogRepository;
	public void log(AuditEventType eventType,
			String email,
			String ip,
			String endPoints,
			boolean success
	) {
		AuditLog log = new AuditLog();
		log.setEventType(eventType);
		log.setEmail(email);
		log.setIpAddress(ip);
		log.setEndpoint(endPoints);
		log.setSuccess(success);
		log.setTimestamp(LocalDateTime.now());
		auditLogRepository.save(log);
	}
	
	
}
