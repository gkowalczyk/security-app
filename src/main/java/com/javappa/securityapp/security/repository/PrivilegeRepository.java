package com.javappa.securityapp.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.javappa.securityapp.security.domain.Privilege;

public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {

    Privilege findByName(String name);

    @Override
    void delete(Privilege privilege);
}