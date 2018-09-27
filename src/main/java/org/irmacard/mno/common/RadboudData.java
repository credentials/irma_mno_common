package org.irmacard.mno.common;

import com.google.gson.reflect.TypeToken;
import org.irmacard.api.common.JwtParser;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;

import java.lang.reflect.Type;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class RadboudData extends AbstractDocumentData {
    private String jwt;
    private transient Map<AttributeIdentifier, String> attrs;
    private transient Key jwtSigningKey;
    private transient String status;
    private transient boolean authenticated = true;

    public RadboudData(String jwt) {
        this.jwt = jwt;
        setCredentialInfo();
    }

    private void setCredentialInfo(){
        this.scheme_manager = "desk-demo";
        this.issuer = "RU";
        this.credential = "radboud";
    }

    public void setJwtSigningKey (Key key){
        this.jwtSigningKey = key;
    }

    public ValidationResult validate (){
        //if (jwtSigningKey == null){
        //    return new ValidationResult(ValidationResult.Result.INVALID, "Error: no JWT signing key found.");
        //}
        parseJWT(true);//TODO:change back to false when api jwt keys are correct
        if (!status.equals("VALID")) {
            return new ValidationResult(ValidationResult.Result.INVALID, "Error: invalid SURF credential.");
        }
        //if (!authenticated){
        //    return new ValidationResult(ValidationResult.Result.INVALID, "Error: SURF jwt was invalid.");
        //}
        return new ValidationResult(ValidationResult.Result.VALID);
    }

    private void parseJWT(boolean allowUnsigned){
        Type t = new TypeToken<Map<AttributeIdentifier, String>>() {}.getType();
        JwtParser<Map<AttributeIdentifier, String>> parser
                = new JwtParser<>(t, allowUnsigned, 3600*1000, "disclosure_result", "attributes");
        if (!allowUnsigned){
            parser.setSigningKey(jwtSigningKey);
        }
        parser.parseJwt(jwt);
        if (!allowUnsigned) {
            authenticated = parser.isAuthenticated();
        }
        attrs = parser.getPayload();
        status = (String) parser.getClaims().get("status");
    }

    public String getDataToReview(){
        if (attrs == null){
            parseJWT(true);
        }
        CredentialIdentifier ci = new CredentialIdentifier("pbdf","pbdf","surfnet");
        StringBuilder sb = new StringBuilder();
        sb.append("Family name: ").append(attrs.get(new AttributeIdentifier(ci,"firstname"))).append("<br/>");
        sb.append("First name: ").append(attrs.get(new AttributeIdentifier(ci,"familyname"))).append("<br/>");
        sb.append("Radboud number: ").append(attrs.get(new AttributeIdentifier(ci, "id"))).append("<br/>");
        return sb.toString();
    }

    public HashMap<String, String> getIssuingJWT(){
        HashMap<String, String> issueAttrs = new HashMap<>();
        CredentialIdentifier ci = new CredentialIdentifier("pbdf","pbdf","surfnet");
        issueAttrs.put("firstname",attrs.get(new AttributeIdentifier(ci,"firstname")));
        issueAttrs.put("familyname",attrs.get(new AttributeIdentifier(ci,"familyname")));
        issueAttrs.put("radboudnr",attrs.get(new AttributeIdentifier(ci, "id")));
        issueAttrs.put("email",attrs.get(new AttributeIdentifier(ci, "email")));
        issueAttrs.put("verificationlevel","FaceToFace");
        return issueAttrs;
    }
}
