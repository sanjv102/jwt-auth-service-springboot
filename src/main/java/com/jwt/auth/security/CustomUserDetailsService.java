package com.jwt.auth.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt.auth.entity.User;
import com.jwt.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService {

	private final UserRepository userRepository;
	public UserDetails loadByUserName(String username) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(username)
					.orElseThrow(()->new UsernameNotFoundException("User not Found"));
					user.getRoles().forEach(r->System.out.println("ROLE LOAD FROM DB: "+r.getName()));
					return new org.springframework.security.core.userdetails.User(
						user.getEmail(), user.getPassword(), 
						user.getRoles()
						.stream()
						.map(r-> new SimpleGrantedAuthority(r.getName()))
						.toList()
					);
	}
	
}
