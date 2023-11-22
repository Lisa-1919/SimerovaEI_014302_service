package com.example.callsdataservice.repository;

import com.example.callsdataservice.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Object> findByName(String name);
}
