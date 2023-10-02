package com.example.demo1.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

  @GetMapping("/demo")
  @PreAuthorize("isAuthenticated()")
  public String demo() {
    return "Demo!";
  }

}
