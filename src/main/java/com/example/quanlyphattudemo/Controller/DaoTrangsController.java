package com.example.quanlyphattudemo.Controller;

import com.example.quanlyphattudemo.Models.DaoTrangs;
import com.example.quanlyphattudemo.Models.PhatTus;
import com.example.quanlyphattudemo.Services.DaoTrangsServices;
import com.google.gson.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Type;
import java.time.LocalDate;

@RestController
@CrossOrigin(value = "*",allowedHeaders = "*")
@RequestMapping(value = "api/version1.0")
public class DaoTrangsController {
    @Autowired
    private DaoTrangsServices daoTrangsServices;
    @PostMapping(value = "/daoTrangs/them")
    public String addNewDaoTrangs(@RequestBody String daoTrangMoi){
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        DaoTrangs dt = gson.fromJson(daoTrangMoi, DaoTrangs.class);
        return daoTrangsServices.addNewDaoTrangs(dt);
    }
    @PutMapping(value = "daoTrangs/sua")
    public DaoTrangs remakeDaoTrangs(@RequestBody String daoTrangSua){
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        DaoTrangs dt = gson.fromJson(daoTrangSua, DaoTrangs.class);
        return daoTrangsServices.remakeDaoTrangs(dt);
    }
    @RequestMapping(value = "daoTrangs/xoa", method = RequestMethod.DELETE,produces = MediaType.APPLICATION_JSON_VALUE)
    public DaoTrangs removeDaoTrang(@RequestParam int daoTrangId) {
       return daoTrangsServices.removeDaoTrang(daoTrangId);
    }
    @GetMapping(value = "daoTrangs/pagefilterDaoTrang")
        public Page<DaoTrangs> pageFilterDaoTrangs(String noiToChuc, String thoiGianToChuc, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "5") int size){
        Pageable pageable =  PageRequest.of(page, size);
        return daoTrangsServices.pageFilterDaoTrangs(noiToChuc,thoiGianToChuc,pageable);
    }
    @GetMapping(value = "daoTrangs/diemDanh")
    public String diemDanh(@RequestParam int daoTrangId){
       return  daoTrangsServices.diemDanh(daoTrangId);
    }
}
