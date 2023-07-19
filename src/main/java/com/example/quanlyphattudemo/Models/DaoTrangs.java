package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "daotrangs")
@Data
public class DaoTrangs {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "noitochuc")
    private String noiToChuc;
    @Column(name = "sothanhvienthamgia")
    private int soThanhVienThamGia;
    @Column(name = "thoigiantochuc")
    private LocalDate thoiGianToChuc;
    @Column(name = "noidung")
    private String noiDung;
    @Column(name = "daketthuc")
    private int daKetThuc;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "nguoichutriid")
    @JsonIgnoreProperties(value = "daoTrangsList")
    @JsonBackReference
    private PhatTus phatTus;
    @OneToMany(mappedBy = "daoTrangs",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "daoTrangs")
    @JsonManagedReference
    private List<PhatTuDaoTrangs> phatTuDaoTrangsList;
    @OneToMany(mappedBy = "daoTrangs",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "daoTrangs")
    @JsonManagedReference
    private List<DonDangKys> donDangKysList;

}
