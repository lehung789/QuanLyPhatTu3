package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.persistence.*;

@Entity
@Table(name = "phattudaotrangs")
@Data
public class PhatTuDaoTrangs {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "dathamgia")
    private int daThamGia;
    @Column(name = "lydokhongthamgia")
    private String lyDoKhongThamGia;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "daotrangid")
    @JsonIgnoreProperties(value = "phatTuDaoTrangsList")
    @JsonBackReference
    private DaoTrangs daoTrangs;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "phattuid")
    @JsonIgnoreProperties(value = "phatTuDaoTrangsList")
    @JsonBackReference
    private PhatTus phatTus;


}
