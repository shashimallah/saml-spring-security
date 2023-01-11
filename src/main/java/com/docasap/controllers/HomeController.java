package com.docasap.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class HomeController {

    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping(value = "/auth")
    public String handleSamlAuth() {
        logger.info("Inside method: handleSamlAuth()");
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

}
