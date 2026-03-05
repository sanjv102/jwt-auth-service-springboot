package com.jwt.auth.entity;

import java.time.LocalDateTime;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name="users")
@Data
public class User {

	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Long id;
	
	@Column(nullable=false)
	private String name;
	
	@Column(nullable=false, unique=true)
	private String email;
	
	@Column(nullable=false)
	private String password;
	
	@ManyToMany(fetch=FetchType.EAGER)
	@JoinTable(
			name="user_roles",
			joinColumns=@JoinColumn(name="user_id"),
			inverseJoinColumns = @JoinColumn(name="role_id")
		)
	private Set<Role> roles;
	
	@Column(nullable=false)
	private boolean enabled=true;
	
	@Column(nullable=false)
	private int failedAttempts=0;
	private LocalDateTime lockTime;
}
