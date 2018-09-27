package org.irmacard.mno.common;

import org.irmacard.credentials.info.CredentialIdentifier;

import java.util.HashMap;
import java.util.List;

public abstract class AbstractDocumentData {
    public static final int RADBOUD = 0;
    public static final int PASSPORT = 1;
    public static final int EDL = 2;


    protected String scheme_manager;
    protected String issuer;
    protected String credential;

    public abstract HashMap<String, String> getIssuingJWT();

    public CredentialIdentifier getCredentialIdentifier(){
        return new CredentialIdentifier(scheme_manager, issuer, credential);
    }

    public abstract ValidationResult validate();


}
