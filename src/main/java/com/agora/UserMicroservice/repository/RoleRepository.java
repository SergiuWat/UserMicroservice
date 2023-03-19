package com.agora.UserMicroservice.repository;

import com.agora.UserMicroservice.entity.ERole;
import com.agora.UserMicroservice.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
