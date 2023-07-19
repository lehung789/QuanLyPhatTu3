package com.example.quanlyphattudemo.Services;

import com.example.quanlyphattudemo.Models.RoleName;
import com.example.quanlyphattudemo.Models.Role;

import java.util.Optional;


public interface IRoleServices {
    Optional<Role> findByName(RoleName name);
}
