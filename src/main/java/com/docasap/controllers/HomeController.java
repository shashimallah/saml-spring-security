package com.docasap.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;


public class HomeController {

    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping(value = "/auth")
    public String handleSamlAuth() {
        logger.info("Inside method: handleSamlAuth()");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            return "redirect:/home";
        } else {
            return "/";
        }
    }

    @RequestMapping("/saml/SSO")
    public String getSamlAcs() {
        logger.info("Inside method: getSamlAcs()");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            return "redirect:/home";
        } else {
            return "/";
        }
    }


    @RequestMapping("/home")
    public String home(Model model) {
        logger.info("Inside method: home()");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", authentication.getPrincipal());
        return "home";
    }

    @GetMapping("/home")
    public String redirectToHome(){
        return "home";
    }


}
