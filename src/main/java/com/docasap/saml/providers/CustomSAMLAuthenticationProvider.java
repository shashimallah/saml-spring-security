package com.docasap.saml.providers;

import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

public class CustomSAMLAuthenticationProvider extends SAMLAuthenticationProvider {

    //Override methods in case of different data
    @Override
    protected Object getUserDetails(SAMLCredential credential) {
        Object userDetails = credential.getNameID().getValue();
        return userDetails;
    }
}
