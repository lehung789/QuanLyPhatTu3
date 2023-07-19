package com.example.quanlyphattudemo.Services;

import com.example.quanlyphattudemo.Models.DaoTrangs;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;



public interface IDaoTrangsServices {
    public String addNewDaoTrangs(DaoTrangs daoTrangMoi);
    public DaoTrangs remakeDaoTrangs(DaoTrangs daoTrangSua);
    public DaoTrangs removeDaoTrang(int daoTrangId);
    public Page<DaoTrangs> pageFilterDaoTrangs(String noiToChuc, String thoiGianToChuc, Pageable pageable);
   // public void diemDanh(int daoTrangId);

}
