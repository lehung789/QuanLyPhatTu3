package com.example.quanlyphattudemo.Repository;

import com.example.quanlyphattudemo.Models.PhatTus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PhatTusRepository extends JpaRepository<PhatTus, Integer> {

    @Query(value = "select * from phattus where ten=?1", nativeQuery = true)
    List<PhatTus> getten(String name);

    @Query(value = "select * from phattus where PhapDanh=?1", nativeQuery = true)
    List<PhatTus> getPhapDanh(String phapDanh);

    @Query(value = "select * from phattus where GioiTinh=?1", nativeQuery = true)
    List<PhatTus> getGioiTinh(int gioiTinh);

    @Query(value = "select * from phattus where dahoantuc=?1", nativeQuery = true)
    List<PhatTus> getTrangThai(int trangThai);

    //    @Query(value = "select * from phattus where ten=?1 or phapdanh=?2 or gioitinh=?3 or dahoantuc=?4", nativeQuery = true)
//    List<PhatTus> getPhatTu(String name, String phapDanh, String gioiTinh, String trangThai);
    @Query(value = "SELECT * FROM phattus WHERE (?1 IS NULL OR ten = ?1) AND (?2 IS NULL OR phapdanh = ?2) AND (?3 IS NULL OR gioitinh = ?3) AND (?4 IS NULL OR dahoantuc = ?4)",
            countQuery = "SELECT COUNT(*) FROM phattus WHERE (?1 IS NULL OR ten = ?1) AND (?2 IS NULL OR phapdanh = ?2) AND (?3 IS NULL OR gioitinh = ?3) AND (?4 IS NULL OR dahoantuc = ?4)",
            nativeQuery = true)
    List<PhatTus> getPhatTu(String name, String phapDanh, String gioiTinh, String trangThai);

    Optional<PhatTus> findByEmailAndMatKhau(String email, String matKhau);

    @Query(value = "SELECT * FROM phattus WHERE ten = ?1 AND phapdanh = ?2 AND  email = ?3 AND  sodienthoai = ?4", nativeQuery = true)
    Optional<PhatTus> findByTPES(String ten, String phapDanh, String email, String sdt);

    // tìm kiếm email
    Optional<PhatTus> findByEmail(String email);

    // kiểm tra tồn tại
    boolean existsByEmail(String email);
    boolean existsBySoDienThoai(String soDienThoai);

}
