package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "dondangkys")
@Data
public class DonDangKys {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "trangthaidon")
    private int trangThaiDon;
    @Column(name = "ngayguidon")
    private LocalDate ngayGuiDon;
    @Column(name = "ngayxuly")
    private LocalDate ngayXuLy;
    @Column(name = "nguoixulyid")
    private int nguoiXuLyId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "phattuid")
    @JsonIgnoreProperties(value = "donDangKysList")
    @JsonBackReference
    private PhatTus phatTus;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "daotrangid")
    @JsonIgnoreProperties(value = "donDangKysList")
    @JsonBackReference
    private DaoTrangs daoTrangs;


}
