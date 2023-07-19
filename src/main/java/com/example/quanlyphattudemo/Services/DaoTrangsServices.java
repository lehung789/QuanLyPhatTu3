package com.example.quanlyphattudemo.Services;

import com.example.quanlyphattudemo.Models.DaoTrangs;
import com.example.quanlyphattudemo.Models.PhatTuDaoTrangs;
import com.example.quanlyphattudemo.Repository.DaoTrangsRepository;
import com.example.quanlyphattudemo.Repository.PhatTuDaoTrangsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class DaoTrangsServices implements IDaoTrangsServices {
    @Autowired
    private DaoTrangsRepository daoTrangsRepository;
    @Autowired
    private PhatTuDaoTrangsRepository phatTuDaoTrangsRepository;

    @Override
    public String addNewDaoTrangs(DaoTrangs daoTrangMoi) {
        daoTrangMoi.setSoThanhVienThamGia(0);
        daoTrangsRepository.save(daoTrangMoi);
        return "Thêm đạo tràng thành công";
    }

    @Override
    public DaoTrangs remakeDaoTrangs(DaoTrangs daoTrangSua) {
        Optional<DaoTrangs> daoTrangs = daoTrangsRepository.findById(daoTrangSua.getId());
        if (daoTrangs.isEmpty())
            return null;
        DaoTrangs dt = daoTrangs.get();
        //PhatTus pt = dt.getPhatTus();
        dt.setNoiToChuc(daoTrangSua.getNoiToChuc());

        //  dt.setSoThanhVienThamGia(daoTrangSua.getSoThanhVienThamGia());
        dt.setThoiGianToChuc(daoTrangSua.getThoiGianToChuc());
        dt.setNoiDung(daoTrangSua.getNoiDung());
        dt.setDaKetThuc(daoTrangSua.getDaKetThuc());
        dt.setPhatTus(daoTrangSua.getPhatTus());

        daoTrangsRepository.save(dt);
 //       diemDanh(daoTrangSua.getId());
        return dt;
    }

    @Override
    public DaoTrangs removeDaoTrang(int daoTrangId) {
        Optional<DaoTrangs> daoTrangs = daoTrangsRepository.findById(daoTrangId);
        if (daoTrangs.isEmpty())
            return null;
        DaoTrangs dt = daoTrangs.get();
        daoTrangsRepository.delete(dt);
        return dt;
    }

    @Override
    public Page<DaoTrangs> pageFilterDaoTrangs(String noiToChuc, String thoiGianToChuc, Pageable pageable) {
        if (noiToChuc != null || thoiGianToChuc != null) {
            List<DaoTrangs> daoTrangs = daoTrangsRepository.findFilter(noiToChuc, thoiGianToChuc);
            return new PageImpl<>(daoTrangs);
        }
        return daoTrangsRepository.findAll(pageable);
    }

    public String diemDanh(int daoTrangId) {
        Optional<DaoTrangs> daoTrangs = daoTrangsRepository.findById(daoTrangId);
        //    Optional<PhatTuDaoTrangs> phatTuDaoTrangs = phatTuDaoTrangsRepository.findByDaoTrangs(daoTrangId);
        int soNguoiThamGia = 0;
        List<PhatTuDaoTrangs> phatTuDaoTrangsList = phatTuDaoTrangsRepository.findAll();
        for (PhatTuDaoTrangs ptdt : phatTuDaoTrangsList) {
            if (ptdt.getDaoTrangs() == daoTrangs.get() && ptdt.getDaThamGia() == 1){
                soNguoiThamGia++;
            }
        }
        daoTrangs.get().setSoThanhVienThamGia(soNguoiThamGia);
        daoTrangsRepository.save(daoTrangs.get());
        return "Điểm danh thành công";
    }
}
