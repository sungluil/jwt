package com.cos.jwt.controller;

import com.cos.jwt.domain.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/join")
    public String join() {
        User user = new User();
        user.setUsername("stussy");
        user.setPassword(passwordEncoder.encode("121212"));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "가입완료";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
