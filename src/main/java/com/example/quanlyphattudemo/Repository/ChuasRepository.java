package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.Chuas;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ChuasRepository extends JpaRepository<Chuas,Integer> {
}
