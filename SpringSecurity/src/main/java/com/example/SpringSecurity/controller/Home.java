package com.example.SpringSecurity.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Home {

    @RequestMapping("/welcome")
    public String welcome(){
        return "Welcome home";
    }

    @RequestMapping("/test")
    public String test(){
        return "test api for all";
    }
}
