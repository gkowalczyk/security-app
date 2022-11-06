package com.javappa.securityapp.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.javappa.securityapp.security.domain.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByName(String name);

    @Override
    void delete(Role role);
}