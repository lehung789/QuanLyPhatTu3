package com.example.quanlyphattudemo.Security.userPrincipal;


import com.example.quanlyphattudemo.Models.PhatTus;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Column;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder // ho tro k can tao moi contructor rieng le bao nhieu contructor cx dc
// sau khi auth tra ve
// lm viec voi ban sao userDetails
public class UserPrincipal implements UserDetails  {
    private int phatid;
    private String ten;
    private String email;
    @JsonIgnore // view truyen reques lay dl json bo qua k in password(thao tac in ra)
    private String matKhau;
    private String soDienThoai;
    private Collection<? extends GrantedAuthority> roles;
    // nhan vao conlection nhung tra ve 1 list
    /**
     *
     * @return collection role (quuyền) của chính userDetails
     */
    // tra ve principal tra ve chinh tk co moi qh vs userDetails
    public static UserDetails build(PhatTus user){
        // tao list cho dung kieu tra ve cua collec
        // xd user truyen vao tao ban sao
        // cautruc past tu set sang lisst
        // dung stream map thay the forE
        // lay rs doi tuong role
        // tu role hoi tao ra simle
        // GrantedAuthority la container chuwa nhieu simple dai dien cho role
        List<GrantedAuthority> grantedAuthorities = user.getRoles().stream().map(
                role -> new SimpleGrantedAuthority(role.getName().name())
//                /**
//                 admin
//                 */
        ).collect(Collectors.toList());
        return UserPrincipal.builder().phatid(user.getId())
                .email(user.getEmail())
                .matKhau(user.getMatKhau())
                .ten(user.getTen())
                .soDienThoai(user.getSoDienThoai())
                .roles(grantedAuthorities)
                .build();
    }



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return matKhau;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
// tai khoan co khong bi block khong
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
// ma xac nhan co khong het han hay khong
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
// kichs hoat hay chua
    @Override
    public boolean isEnabled() {
        return true;
    }
}
