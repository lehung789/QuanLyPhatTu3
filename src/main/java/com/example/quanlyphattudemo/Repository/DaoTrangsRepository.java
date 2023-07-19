package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.DaoTrangs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DaoTrangsRepository extends JpaRepository<DaoTrangs,Integer> {
    @Query(value = "SELECT * FROM daotrangs WHERE ( ?1 IS NULL OR noitochuc =?1) AND (?2 IS NULL OR thoigiantochuc =?2)", nativeQuery = true)
    List<DaoTrangs> findFilter(String noiToChuc, String thoiGianToChuc);
}
