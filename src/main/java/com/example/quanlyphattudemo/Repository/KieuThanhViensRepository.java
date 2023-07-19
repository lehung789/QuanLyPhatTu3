package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.KieuThanhViens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KieuThanhViensRepository extends JpaRepository<KieuThanhViens,Integer> {
}
