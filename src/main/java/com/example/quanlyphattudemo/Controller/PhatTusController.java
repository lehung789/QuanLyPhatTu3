package com.example.quanlyphattudemo.Controller;

import com.example.quanlyphattudemo.Models.PhatTus;
import com.example.quanlyphattudemo.Services.PhatTusServices;
import com.google.gson.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Type;
import java.time.LocalDate;
import java.util.List;

@RestController
@CrossOrigin(value = "*",allowedHeaders = "*")
@RequestMapping(value = "api/version1.0")
public class PhatTusController {
    @Autowired
    private PhatTusServices phatTusServices;
    @RequestMapping(value = "PhatTus/them",method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public String addNewPhatTu(@RequestBody String ptM){
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        PhatTus pt = gson.fromJson(ptM, PhatTus.class);
        return phatTusServices.addNewPhatTu(pt);
    }
    @RequestMapping(value = "PhatTus/sua",method = RequestMethod.PUT, produces = MediaType.APPLICATION_JSON_VALUE)
    public PhatTus remakePhatTu(@RequestBody String ptS){
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        PhatTus hs = gson.fromJson(ptS, PhatTus.class);

        return phatTusServices.remakePhatTu(hs);
    }
    @RequestMapping(value = "PhatTus/filterName",method = RequestMethod.GET)
    public List<PhatTus> finterName(@RequestParam String name){
        return phatTusServices.filterName(name);
    }
    @RequestMapping(value = "PhatTus/filterPhapDanh",method = RequestMethod.GET)
    public List<PhatTus> filterPhapDanh(@RequestParam String phapDanh){
        return phatTusServices.filterPhapDanh(phapDanh);
    }
    @RequestMapping(value = "PhatTus/filterGioiTinh",method = RequestMethod.GET)
    public List<PhatTus> filterGioiTinh(@RequestParam int gioiTinh){
        return phatTusServices.filterGioiTinh(gioiTinh);
    }
    @RequestMapping(value = "PhatTus/getAll",method = RequestMethod.GET)
    public List<PhatTus> getAll(){
        return phatTusServices.getAll();
    }
    @RequestMapping(value = "PhatTus/phanTrang",method = RequestMethod.GET)
    public Page<PhatTus> phanTrangPhatTu(@RequestParam int page, int size){
        return phatTusServices.phanTrangPhatTu(page,size);
    }
    @RequestMapping(value = "PhatTus/pageName",method = RequestMethod.GET)
    public Page<PhatTus> pageName(@RequestParam String name,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "1") int size){
        Pageable pageable =  PageRequest.of(page, size);
        return phatTusServices.pageName(name, page, size);
    }
    @RequestMapping(value = "PhatTus/pagePhapDanh",method = RequestMethod.GET)
    public Page<PhatTus> pagePhapDanh(@RequestParam String phapDanh,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "1") int size){
        return phatTusServices.pagePhapDanh(phapDanh, page, size);
    }
    @RequestMapping(value = "PhatTus/pageGioiTinh",method = RequestMethod.GET)
    public Page<PhatTus> pageGioiTinh(@RequestParam int gioiTinh,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "1") int size){
        return phatTusServices.pageGioiTinh(gioiTinh, page, size);
    }
    @GetMapping("PhatTus/pageTrangThai")
    public Page<PhatTus> pageTrangThai(@RequestParam int trangThai,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "1") int size){
        return phatTusServices.pageTrangThai(trangThai, page, size);
    }
    @RequestMapping(value = "PhatTus/pagePhatTu",method = RequestMethod.GET)
    public Page<PhatTus> pagePhatTu( String name,  String phapDanh, String gioiTinh, String trangThai,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "5") int size){
        Pageable pageable =  PageRequest.of(page, size);
        return phatTusServices.pagePhatTu(name, phapDanh,gioiTinh,trangThai,pageable);
    }
    @RequestMapping(value = "PhatTus/dangKi", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public String addNewDangKi(@RequestBody String pt){
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        PhatTus ptdk = gson.fromJson(pt, PhatTus.class);
        return phatTusServices.addNewDangKi(ptdk);
    }
    @GetMapping("PhatTus/login")
    public String login(String email, String matKhau){
        return phatTusServices.login(email,matKhau);
    }
    @GetMapping("PhatTus/doiMatKhau")
    public String doiMatKhau( @RequestParam String email, String matKhau, String newPassword){
        return phatTusServices.doiMatKhau(email,matKhau,newPassword);
    }
    @RequestMapping(value = "PhatTus/addNewDonDangKi", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public String addNewDonDangKi( String ten, String phapDanh, String email, String sdt,int daoTrangId){
        return phatTusServices.addNewDonDangKi(ten,phapDanh,email,sdt,daoTrangId);
    }
    @RequestMapping(value = "PhatTus/xuLyDon", method = RequestMethod.PUT, produces = MediaType.APPLICATION_JSON_VALUE)
    public String xuLyDon(@RequestParam int donDangKiId,@RequestParam int trangThai,@RequestParam int nguoiXuLy){
        return phatTusServices.xuLyDon(donDangKiId,trangThai,nguoiXuLy);
    }
    @GetMapping("PhatTus/loginOnline")
    public String online(String email, String matKhau){
        return phatTusServices.online(email,matKhau);
    }
    @GetMapping ("PhatTus/logout")
    public String logout(@RequestParam String email){
        return phatTusServices.logout(email);
    }
}
