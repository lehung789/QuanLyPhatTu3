package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.DonDangKys;
import com.example.quanlyphattudemo.Models.PhatTus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface DonDangKysRepository extends JpaRepository<DonDangKys,Integer> {
    Optional<DonDangKys> findByPhatTus(PhatTus phatTus);
}
