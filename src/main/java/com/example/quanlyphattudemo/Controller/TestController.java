package com.example.quanlyphattudemo.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/test")
public class TestController {
    @GetMapping("/all")
    public String allAcces() {
        return "Public content";
    }

    @GetMapping("/user")
  //  @PreAuthorize("hasAnyAuthority('USER') or hasAnyAuthority('MODERATOR') or hasAnyAuthority('ADMIN')")
    public String userAccess() {
        return "UserContent";
    }

    @GetMapping("/mod")
  //  @PreAuthorize("hasAnyAuthority('MODERATOR') or hasAnyAuthority('ADMIN')")
    public String moderatoruserAccess() {
        return "Moderator Board.";
    }

    @GetMapping("/admin")
  //   @PreAuthorize(" hasAnyAuthority('ADMIN')")
    public String adminAccess() {
        return "admin Board.";
    }
}
