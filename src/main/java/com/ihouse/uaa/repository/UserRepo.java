package com.ihouse.uaa.repository;

import com.ihouse.uaa.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {

    long countByEmailAndUsernameIsNot(String email,String username);

    long countByMobileAndUsernameIsNot(String mobile,String username);

    Optional<User> findOptionalByUsername(String username);

    long countByUsername(String username);

    long countByEmail(String email);

    long countByMobile(String mobile);
}
