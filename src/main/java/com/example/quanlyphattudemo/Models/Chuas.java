package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "chuas")
@Data
public class Chuas {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "tenchua")
    private String tenChua;
    @Column(name = "ngaythanhlap")
    private LocalDate ngayThanhLap;
    @Column(name = "diachi")
    private String diaChi;
    @Column(name = "trutri")
    private String truTri;
    @Column(name = "capnhap")
    private LocalDate capNhap;
    @OneToMany(mappedBy = "chuas",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "chuas")
    @JsonBackReference
    private List<PhatTus> phatTusList;


}
