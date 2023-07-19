package com.example.quanlyphattudemo.Models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "kieuthanhviens")
@Data
public class KieuThanhViens {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String code;
    @Column(name = "tenkieu")
    private String tenKieu;
    @OneToMany(mappedBy = "kieuThanhViens",cascade = CascadeType.ALL)
    @JsonIgnoreProperties(value = "kieuThanhViens")
    @JsonManagedReference
    private List<PhatTus> phatTusList;


}
