package com.example.quanlyphattudemo.Services;

import com.example.quanlyphattudemo.Models.PhatTus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface IPhatTusServices {
    public String addNewPhatTu(PhatTus ptM);
    public PhatTus remakePhatTu(PhatTus ptS);
    public List<PhatTus> filterName(String name);
    public List<PhatTus> filterPhapDanh(String phapDanh);
    public List<PhatTus> filterGioiTinh(int gioiTinh);
    public List<PhatTus> getAll();
    public Page<PhatTus> phanTrangPhatTu(int page, int size);
    public Page<PhatTus> pageName(String name, int page, int size);
    public Page<PhatTus> pagePhapDanh(String phapDanh, int page, int size);
    public Page<PhatTus> pageGioiTinh(int gioiTinh, int page, int size);
    public Page<PhatTus> pageTrangThai(int trangThai, int page, int size);
    public Page<PhatTus> pagePhatTu(String name, String phapDanh, String gioiTinh, String trangThai, Pageable pageable);
    public String addNewDangKi(PhatTus ptDK);
    public String login(String email, String matKhau);
    public String doiMatKhau(String email, String matKhau, String newPassword);
    public  String addNewDonDangKi(String ten, String phapDanh, String email, String sdt, int daoTrangId );
    public String xuLyDon(int donDangKi, int trangThai, int nguoiXyLy);
    public String online(String email, String matKhau);
    public String logout(String email);
    // tìm kiếm email
    Optional<PhatTus> findByEmail(String email);

    // kiểm tra tồn tại
    boolean existsByEmail(String email);
    boolean existsBySoDienThoai(String soDienThoai);
    PhatTus save(PhatTus phatTus);
}
