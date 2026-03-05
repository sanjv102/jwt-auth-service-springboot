package com.jwt.auth.entity;

import java.security.cert.TrustAnchor;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name="refresh_token")
@Data
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Column(nullable = false, length = 512, unique = true)
	private String token;
	private Instant expiryDate;
	private boolean revoked=false;
	
	@ManyToOne
	@JoinColumn(name="user_id")
	private User user;
	
}
