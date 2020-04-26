package com.fwtai.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {

    @GetMapping("/api/guest")
    public String guest(){
        return "This is a guest api msg";
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin(){
        return "This is an admin api msg";
    }
}