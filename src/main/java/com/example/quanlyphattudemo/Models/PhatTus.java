package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "phattus")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PhatTus {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String ho;
    @Column(name = "tendem")
    private String tenDem;
    private String ten;
    @Column(name = "phapdanh")
    private String phapDanh;
    @Column(name = "anhchup")
    private String anhChup;
    @Column(name = "sodienthoai")
    private String soDienThoai;
    @Column(unique = true,nullable = false)
    private String email;
    @Column(name = "matkhau",nullable = false)
    private String matKhau;
    @Column(name = "ngaysinh")
    private LocalDate ngaySinh;
    @Column(name = "ngayxuatgia")
    private LocalDate ngayXuatGia;
    @Column(name = "dahoantuc")
    private int daHoanTuc;
    @Column(name = "ngayhoantuc")
    private LocalDate ngayHoanTuc;
    @Column(name = "gioitinh")
    private int gioiTinh;
    @Column(name = "ngaycapnhap")
    private LocalDate ngayCapNhap;
    private int online;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "kieuthanhvienid")
    @JsonIgnoreProperties(value = "phatTusList")
    @JsonBackReference
    private KieuThanhViens kieuThanhViens;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "chuaid")
    @JsonIgnoreProperties(value = "phatTusList")
    @JsonBackReference
    private Chuas chuas;
    @OneToMany(mappedBy = "phatTus",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "phatTus")
    @JsonManagedReference
    private List<DaoTrangs> daoTrangsList;
    @OneToMany(mappedBy = "phatTus",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "phatTus")
    @JsonManagedReference
    private List<PhatTuDaoTrangs> phatTuDaoTrangsList;
    @OneToMany(mappedBy = "phatTus",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "phatTus")
    @JsonManagedReference
    private List<DonDangKys> donDangKysList;
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "User_Role",
            joinColumns = @JoinColumn(name = "UserId"),
            inverseJoinColumns = @JoinColumn(name = "RoleId"))

    private Set<Role> roles  = new HashSet<>();

}
