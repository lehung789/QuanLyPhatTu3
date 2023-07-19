package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.RoleName;
import com.example.quanlyphattudemo.Models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(RoleName name);
}
