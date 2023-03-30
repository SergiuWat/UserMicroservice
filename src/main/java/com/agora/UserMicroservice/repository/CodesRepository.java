package com.agora.UserMicroservice.repository;

import com.agora.UserMicroservice.entity.Codes;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CodesRepository extends JpaRepository<Codes, Long> {

    Codes findByCode(String code);
}
