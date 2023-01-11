package com.docasap.config;


import com.docasap.saml.providers.CustomSAMLAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig {

    @Autowired
    SAMLEntryPoint samlEntryPoint;

    @Autowired
    SavedRequestAwareAuthenticationSuccessHandler samlAuthSuccessHandler;

    @Autowired
    SimpleUrlAuthenticationFailureHandler samlAuthFailureHandler;

    @Autowired
    MetadataGeneratorFilter metadataGeneratorFilter;

    @Autowired
    SAMLLogoutFilter samlLogoutFilter;

    @Autowired
    SAMLLogoutProcessingFilter samlLogoutProcessingFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.httpBasic().authenticationEntryPoint(samlEntryPoint);
        http.addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(samlFilter(), CsrfFilter.class);
        http.authorizeRequests(authorize ->
                authorize.antMatchers("/").permitAll().
                        anyRequest().authenticated()
        );
        http.logout()
                .addLogoutHandler((request, response, authentication) -> {
                    try {
                        response.sendRedirect("/saml/logout");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        return http.build();
    }

    @Bean
    public FilterChainProxy samlFilter() {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
                samlDiscovery()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter));
        return new FilterChainProxy(chains);
    }


    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(samlAuthSuccessHandler);
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(samlAuthFailureHandler);
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        CustomSAMLAuthenticationProvider customSAMLAuthenticationProvider = new CustomSAMLAuthenticationProvider();
        customSAMLAuthenticationProvider.setConsumer(webSSOprofileConsumer());
        return customSAMLAuthenticationProvider;
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(samlAuthenticationProvider()));
    }

    public SAMLDiscovery samlDiscovery() {
        return new SAMLDiscovery();
    }

}
