package com.example.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableMethodSecurity
public class Controller {
    @GetMapping("/hello")
    public String hello(){
        return "Hello";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint(){
        return "Hello, USER";
    }
    @PreAuthorize(("hasRole('ADMIN')"))
    @GetMapping("/admin")
    public String adminendpoint(){
        return "Hello";
    }
}
