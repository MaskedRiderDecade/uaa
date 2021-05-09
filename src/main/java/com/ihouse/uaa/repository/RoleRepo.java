package com.ihouse.uaa.repository;

import com.ihouse.uaa.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleRepo extends JpaRepository<Role, Long> {
    Optional<Role> findOptionalByAuthority(String authority);
}
