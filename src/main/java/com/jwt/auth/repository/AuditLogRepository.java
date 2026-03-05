package com.jwt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.auth.audit.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long>{

}
