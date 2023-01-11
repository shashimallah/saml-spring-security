package com.docasap.saml.providers;

import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

public class CustomSAMLAuthenticationProvider extends SAMLAuthenticationProvider {

    //Override methods in case of different type of user objects
    @Override
    protected Object getUserDetails(SAMLCredential credential) {
        return credential.getNameID().getValue();
    }

}
