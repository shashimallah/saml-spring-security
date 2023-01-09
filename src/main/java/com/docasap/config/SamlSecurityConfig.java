package com.docasap.config;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.*;

@Configuration
public class SamlSecurityConfig {

    @Value("${onelogin.saml2.sp.entityid}")
    private String samlAudience;

    @Bean
    @Qualifier("onelogin")
    public ExtendedMetadataDelegate oneloginExtendedMetadataProvider() throws MetadataProviderException, ResourceException, ConfigurationException {
        Resource resource = new ClasspathResource("/saml/onelogin-metadata.xml");
        Timer timer = new Timer("saml-metadata");
        ResourceBackedMetadataProvider resourceBackedMetadataProvider = new ResourceBackedMetadataProvider(timer, resource);
        resourceBackedMetadataProvider.setParserPool(parserPool());
        DefaultBootstrap.bootstrap();
        return new ExtendedMetadataDelegate(resourceBackedMetadataProvider, extendedMetadata());
    }

    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException, ConfigurationException {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(oneloginExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(samlAudience);
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    @Bean
    public JKSKeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        org.springframework.core.io.Resource storeFile = loader
                .getResource("classpath:/saml/saml-keystore.jks");
        String storePass = "saml-spring-security";
        Map<String, String> passwords = new HashMap<>();
        passwords.put("saml-spring-security", "saml-spring-security");
        String defaultKey = "saml-spring-security";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
//        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }


    @Bean
    @Qualifier("saml")
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/home");
        return successRedirectHandler;
    }

    @Bean
    @Qualifier("saml")
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }

}
