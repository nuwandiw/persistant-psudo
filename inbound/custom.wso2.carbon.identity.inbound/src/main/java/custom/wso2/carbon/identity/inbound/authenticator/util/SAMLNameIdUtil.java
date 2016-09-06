package custom.wso2.carbon.identity.inbound.authenticator.util;

import org.opensaml.saml2.core.ManageNameIDRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.core.validator.ManageNameIDRequestSchemaValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

public class SAMLNameIdUtil {

    public static ManageNameIDRequest getNameIDRequestObject(String samlRequest) throws AuthenticationFailedException {
        ManageNameIDRequestSchemaValidator validator= new ManageNameIDRequestSchemaValidator();
        try {
            XMLObject request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(samlRequest));
            if (request instanceof ManageNameIDRequest) {
                validator.validate((ManageNameIDRequest) request);
                return (ManageNameIDRequest) request;
            } else {
                throw new AuthenticationFailedException("Invalid user unregistration request");
            }
        } catch (IdentityException e) {
            throw new AuthenticationFailedException("Error while processing request. Unregistration failed");
        } catch (ValidationException e) {
            throw new AuthenticationFailedException("Invalid ManageNameIDRequest. Unregistration failed");
        }
    }

    public static Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    public String getNameIdFromRequest(ManageNameIDRequest nameIDRequest){
        NameID nameId = nameIDRequest.getNameID();
        return nameId.getValue();
    }
}
