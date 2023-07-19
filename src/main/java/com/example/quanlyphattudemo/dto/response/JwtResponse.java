package com.example.quanlyphattudemo.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtResponse {
    private String status;
    private String token;
    private String type;
    private String ten;
    private Collection<? extends GrantedAuthority> roles;
}
