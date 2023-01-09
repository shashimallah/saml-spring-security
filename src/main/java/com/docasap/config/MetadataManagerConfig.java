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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;

@Configuration
public class MetadataManagerConfig {

    @Value("${onelogin.saml2.idp.entity_id}")
    String defaultIdp;

    @Autowired
    ExtendedMetadata extendedMetadata;

    @Autowired
    StaticBasicParserPool parserPool;

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do not forget to call initialize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException, ConfigurationException {
        List<MetadataProvider> providers = new ArrayList<>();
        ExtendedMetadataDelegate extendedMetadataDelegate = oneloginExtendedMetadataProvider();
        providers.add(extendedMetadataDelegate);
        CachingMetadataManager metadataManager = new CachingMetadataManager(providers);
        metadataManager.setDefaultIDP(defaultIdp);
        return metadataManager;
    }

    @Bean
    @Qualifier("onelogin")
    public ExtendedMetadataDelegate oneloginExtendedMetadataProvider() throws MetadataProviderException, ResourceException, ConfigurationException {
        Resource resource = new ClasspathResource("/saml/onelogin-metadata.xml");
        Timer timer = new Timer("saml-metadata");
        ResourceBackedMetadataProvider resourceBackedMetadataProvider = new ResourceBackedMetadataProvider(timer, resource);
        resourceBackedMetadataProvider.setParserPool(parserPool);
        DefaultBootstrap.bootstrap();
        return new ExtendedMetadataDelegate(resourceBackedMetadataProvider, extendedMetadata);
    }

}
