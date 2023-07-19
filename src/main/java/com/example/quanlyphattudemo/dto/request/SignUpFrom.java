package com.example.quanlyphattudemo.dto.request;

import com.example.quanlyphattudemo.Models.Chuas;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SignUpFrom {
    private String ho;
    private String tenDem;
    private String ten;
    private LocalDate ngaySinh;
    private String phapDanh;
    private String email;
    private String matKhau;
    private String soDienThoai;
    private int gioiTinh;
    private Chuas chuas;
    private Set<String> roles;

}
