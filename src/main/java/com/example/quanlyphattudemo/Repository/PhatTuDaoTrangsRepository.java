package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.PhatTuDaoTrangs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PhatTuDaoTrangsRepository extends JpaRepository<PhatTuDaoTrangs,Integer> {
    Optional<PhatTuDaoTrangs> findByDaoTrangs(int daoTrangId);

}
