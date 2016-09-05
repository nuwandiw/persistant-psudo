package custom.wso2.carbon.identity.application.authenticator.persistantId.util;

import custom.wso2.carbon.identity.application.authenticator.persistantId.SymcorAuthenticatorConstants;
import org.opensaml.saml2.core.ManageNameIDRequest;
import org.opensaml.saml2.core.validator.ManageNameIDRequestSchemaValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

public class SymcorAuthenticatorUtil {

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

    public static String getNameIDRequestId (AuthenticationContext context) throws AuthenticationFailedException {
        String manageNameIdRequest = context.getAuthenticationRequest().
                getRequestQueryParam(SymcorAuthenticatorConstants.HTTP_PARAM_SAML_NAMEID_REQUEST)[0];
        ManageNameIDRequest request = getNameIDRequestObject(manageNameIdRequest);
        return request.getID();
    }
}
