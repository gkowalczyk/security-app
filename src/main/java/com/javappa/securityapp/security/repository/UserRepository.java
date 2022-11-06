package com.javappa.securityapp.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import com.javappa.securityapp.security.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
	
	@Transactional
	User findByEmail(String email);

	@Override
	void delete(User user);
}