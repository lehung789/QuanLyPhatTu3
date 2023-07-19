package com.example.quanlyphattudemo.Controller;


import com.example.quanlyphattudemo.Models.PhatTus;
import com.example.quanlyphattudemo.Models.Role;
import com.example.quanlyphattudemo.Models.RoleName;
import com.example.quanlyphattudemo.Security.jwt.JwtProvider;
import com.example.quanlyphattudemo.Security.userPrincipal.UserPrincipal;
import com.example.quanlyphattudemo.Services.PhatTusServices;
import com.example.quanlyphattudemo.Services.RoleServices;
import com.example.quanlyphattudemo.dto.request.SignInFrom;
import com.example.quanlyphattudemo.dto.request.SignUpFrom;
import com.example.quanlyphattudemo.dto.response.JwtResponse;
import com.example.quanlyphattudemo.dto.response.ResponseMessage;
import com.google.gson.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Type;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v6/auth")
@RequiredArgsConstructor
public class AuthController {
    private final PhatTusServices phatTusServices;
    private final RoleServices roleServices;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager; // dc sd nhờ bean
    private final JwtProvider jwtProvider;


    @PostMapping("singUp")
    public ResponseEntity<ResponseMessage> signUp(@RequestBody String signUp) {
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new JsonDeserializer<LocalDate>() {
            @Override
            public LocalDate deserialize(JsonElement json, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                return LocalDate.parse(json.getAsJsonPrimitive().getAsString());
            }
        }).create();
        SignUpFrom signUpFrom = gson.fromJson(signUp, SignUpFrom.class);
        boolean isExistUsername = phatTusServices.existsByEmail(signUpFrom.getEmail());
        if (isExistUsername){
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(
                    ResponseMessage.builder()
                            .status("FAILED")
                            .message("This username is already existed!")
                            .data("")
                            .build()
            );
        }
        boolean isExistPhoneNumber = phatTusServices.existsBySoDienThoai(signUpFrom.getSoDienThoai());
        if (isExistPhoneNumber){
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(
                    ResponseMessage.builder()
                            .status("FAILED")
                            .message("This username is already existed!")
                            .data("")
                            .build()
            );
        }
        Set<Role> roles = new HashSet<>();
        if (signUpFrom.getRoles() == null || signUpFrom.getRoles().isEmpty()){
            Role role = roleServices.findByName(RoleName.USER)
                    .orElseThrow(() -> new RuntimeException("Failed -> NOT FOUND ROLE"));
            roles.add(role);
        }else {
            signUpFrom.getRoles().forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleServices.findByName(RoleName.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Failed -> NOT FOUND ROLE"));
                        roles.add(adminRole);
                    case "moderator":
                        Role pmRole = roleServices.findByName(RoleName.MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Failed -> NOT FOUND ROLE"));
                        roles.add(pmRole);
                    case "user":
                        Role userRole = roleServices.findByName(RoleName.USER)
                                .orElseThrow(() -> new RuntimeException("Failed -> NOT FOUND ROLE"));
                        roles.add(userRole);
                }
            });
        }
        String password = signUpFrom.getMatKhau(); // Assuming `password` is the variable containing the password
        if (phatTusServices.testPassword(password)) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Error: Password must contain at least one digit or one character"));
        }
        PhatTus user = PhatTus.builder()
                .ho(signUpFrom.getHo())
                .tenDem(signUpFrom.getTenDem())
                .ten(signUpFrom.getTen())
                .phapDanh(signUpFrom.getPhapDanh())
                .email(signUpFrom.getEmail())
                .matKhau(passwordEncoder.encode(signUpFrom.getMatKhau()))
                .ngaySinh(signUpFrom.getNgaySinh())
                .soDienThoai(signUpFrom.getSoDienThoai())
                .gioiTinh(signUpFrom.getGioiTinh())
                .chuas(signUpFrom.getChuas())
                .roles(roles)
                .build();
        //iUserSevice.save(user)
        return ResponseEntity.ok().body(
                ResponseMessage.builder()
                        .status("OK")
                        .message("Account created successfully!")
                        .data(phatTusServices.save(user))
                        .build()
        );
    }
    @PostMapping("/signIn")
    public ResponseEntity<?> doSignIn(@RequestBody SignInFrom signInFrom){
        try{
            Authentication authentication =  authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            signInFrom.getEmail(),
                            signInFrom.getMatKhau())
                    );

            String token = jwtProvider.generateToken(authentication);
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return new ResponseEntity<>(
                    JwtResponse.builder()
                            .status("OK")
                            .type("Bearer")
                            .ten(userPrincipal.getTen())
                            .token(token)
                            .roles(userPrincipal.getAuthorities())
                            .build(), HttpStatus.OK);

        }catch (AuthenticationException e){
            return new ResponseEntity<>(
                    ResponseMessage.builder()
                    .status("Faild")
                    .message("Invalid username or password!")
                    .data("")
                    .build(), HttpStatus.UNAUTHORIZED);
        }


    }
}
