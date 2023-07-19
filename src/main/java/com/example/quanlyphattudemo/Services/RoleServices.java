package com.example.quanlyphattudemo.Services;

import com.example.quanlyphattudemo.Models.RoleName;
import com.example.quanlyphattudemo.Models.Role;
import com.example.quanlyphattudemo.Repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServices implements IRoleServices{
    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Optional<Role> findByName(RoleName name) {
        return roleRepository.findByName(name);
    }
}
