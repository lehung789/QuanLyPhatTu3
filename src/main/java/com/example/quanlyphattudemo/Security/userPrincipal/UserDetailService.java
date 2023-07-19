package com.example.quanlyphattudemo.Security.userPrincipal;

import com.example.quanlyphattudemo.Models.PhatTus;
import com.example.quanlyphattudemo.Repository.PhatTusRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailService implements UserDetailsService {
    // tra va userdetail dua vao userName
    private final PhatTusRepository phatTusRepository;
   // tìm kiếm thông tin về người dùng trong hệ thống dựa trên tên đăng nhập
    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
        PhatTus user = phatTusRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Failed -> Not Found User at username: "+ email) );
        return UserPrincipal.build(user);
    }
}
