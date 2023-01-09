package com.docasap.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class MetadataGeneratorConfig {

    @Value("${onelogin.saml2.sp.entity_id}")
    String samlAudience;

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
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        // To use default Metadata Manager this attribute should be empty
        extendedMetadata.setKeyInfoGeneratorName("");
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
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

}
