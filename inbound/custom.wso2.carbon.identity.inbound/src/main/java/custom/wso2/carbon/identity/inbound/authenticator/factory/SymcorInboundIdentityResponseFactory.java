package custom.wso2.carbon.identity.inbound.authenticator.factory;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.dao.SymcorInboundDAO;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundResponse;
import custom.wso2.carbon.identity.inbound.authenticator.util.SAMLNameIdUtil;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymmetricEncrypter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ManageNameIDRequest;
import org.opensaml.saml2.core.ManageNameIDResponse;
import org.opensaml.saml2.core.impl.ManageNameIDResponseBuilder;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Iterator;
import java.util.Map;


public class SymcorInboundIdentityResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(SymcorInboundIdentityResponseFactory.class);

    public String getName() {
        return "SymcorInboundIdentityResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof SymcorInboundResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder
                = new HttpIdentityResponse.HttpIdentityResponseBuilder();

        AuthenticationResult authResult = ((SymcorInboundResponse) identityResponse).getAuthenticationResult();

        if (authResult != null && authResult.isAuthenticated()) {
            buildResponseForApp(builder, identityResponse);
        } else if (((SymcorInboundResponse) identityResponse).getNameIdRequest() != null) {
            doUnregistration(identityResponse);
            buildNameIdResponseForIdp(builder, identityResponse);
        }
        else {
            builder.setStatusCode(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            builder.setRedirectURL(getPropertyValue(identityResponse, SymcorInboundConstants.IDP_URl));
        }
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {
        return null;
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder buildNameIdResponseForIdp(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        String response = buildManageNameIDResponse(identityResponse);
        builder.addParameter(SymcorInboundConstants.NAME_ID_RESPONSE, response);
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(getPropertyValue(identityResponse, SymcorInboundConstants.IDP_URl));
        return builder;
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder buildResponseForApp(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        builder.addParameter(SymcorInboundConstants.PLATFORM_INFO, getPlatformInfo(identityResponse));
        builder.addParameter(SymcorInboundConstants.USER_TOKEN, getEncryptedToken(identityResponse));
        String language = getLanguage(identityResponse);
        if (language != null) {
            builder.addParameter(SymcorInboundConstants.LANGUAGE, language);
        }
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(getRedirectUrl(identityResponse));
        return builder;
    }

    private String getClaimValue (AuthenticatedUser user, String claimUri) {
        String claimValue = null;
        Map<ClaimMapping, String> claims = user.getUserAttributes();
        Iterator it = claims.entrySet().iterator();
        while (it.hasNext()){
            Map.Entry pair = (Map.Entry)it.next();
            ClaimMapping claim = (ClaimMapping)pair.getKey();

            if (claimUri.equals(claim.getLocalClaim().getClaimUri())) {
                claimValue = (String) pair.getValue();
            }
        }
        return claimValue;
    }

    private String getPropertyValue(IdentityResponse identityResponse, String property) {
        String propertyValue = null;
        String tenantDomain = ((SymcorInboundResponse) identityResponse).getTenantDomain();
        Property[] props = getInboundAuthenticatorPropertyArray(identityResponse, tenantDomain);
        for (Property prop : props) {
            if (prop.getName().equals(property)) {
                propertyValue = prop.getValue();
                break;
            }
        }
        return propertyValue;
    }

    private Property[] getInboundAuthenticatorPropertyArray(IdentityResponse identityResponse, String tenantDomain) {
        String relyingParty = ((SymcorInboundResponse) identityResponse).getRelyingParty();
        Property[] properties = null;
        try {
            ServiceProvider sp =
                    ApplicationManagementServiceImpl.getInstance().getServiceProvider(relyingParty, tenantDomain);
            if (sp == null) {
                throw new RuntimeException("No service provider configuration found for :" + relyingParty);
            }
            sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
            for (InboundAuthenticationRequestConfig config :
                    sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                if (config.getInboundAuthType().equals(((SymcorInboundResponse) identityResponse).getAuthType())) {
                    properties = config.getProperties();
                    break;
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw new RuntimeException("Error while reading inbound authenticator properties");
        }
        return properties;
    }

    private String getRedirectUrl(IdentityResponse identityResponse) {
        String redirectURL;
        String platformInfo = getPlatformInfo(identityResponse);

        if ("0".equals(platformInfo) || "2".equals(platformInfo)) {
            redirectURL = getPropertyValue(identityResponse,
                    SymcorInboundConstants.NEW_PLATFORM_PROPERTY);

        } else if ("1".equals(platformInfo)) {
            redirectURL = getPropertyValue(identityResponse,
                    SymcorInboundConstants.OLD_PLATFORM_PROPERTY);
        } else {
            throw new RuntimeException("Invalid platform info. Cannot decide redirect URL");
        }
        return redirectURL;
    }

    private String getPlatformInfo(IdentityResponse identityResponse) {
        return getClaimValue(
                ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject(),
                SymcorInboundConstants.PLATFORM_INFO_CLAIM);
    }

    private String getLanguage(IdentityResponse identityResponse) {
        return getClaimValue(
                ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject(),
                SymcorInboundConstants.LANGUAGE_CLAIM);
    }

    private String getEncryptedToken(IdentityResponse identityResponse) {
        byte[] encryptedData;
        try {
            String userName = ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject().getUserName();
            encryptedData = SymmetricEncrypter.encryptWithSymmetricKey(userName.getBytes(StandardCharsets.UTF_8));
        } catch (CryptoException e) {
            throw new RuntimeException("Error while encrypting userID", e);
        }
        return Base64.encodeBase64String(encryptedData);
    }

    private void doUnregistration(IdentityResponse response) {

        ManageNameIDRequest request = ((SymcorInboundResponse)response).getNameIdRequest();
        SymcorInboundDAO dao = new SymcorInboundDAO();
        String nameId = request.getNameID().getValue();
        try {
            String userName = dao.getUsernameForNameID(nameId);
            if (userName != null) {
                dao.removeNameID(nameId);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Error while updating SSO_SP_USER. Unregistration failed");
        }
    }

    private String buildManageNameIDResponse (IdentityResponse identityResponse) {

        String manageNameIdResponse = null;
        try {
            ManageNameIDResponseBuilder responseBuilder = new ManageNameIDResponseBuilder();
            ManageNameIDResponse response = responseBuilder.buildObject();

            SymcorInboundResponse symcorInboundResponse = (SymcorInboundResponse) identityResponse;

            response.setID(SAMLSSOUtil.createID());
            response.setInResponseTo(symcorInboundResponse.getNameIdRequest().getID());
            response.setDestination(getPropertyValue(identityResponse, SymcorInboundConstants.IDP_URl));
            response.setVersion(SAMLVersion.VERSION_20);

            DateTime issueInstant = new DateTime();
            response.setIssueInstant(issueInstant);

            String tenantDomain = ((SymcorInboundResponse) identityResponse).getTenantDomain();
            response.setIssuer(SAMLSSOUtil.getIssuerFromTenantDomain(tenantDomain));

            response.setStatus(SAMLNameIdUtil.buildStatus(
                    SAMLSSOConstants.StatusCodes.SUCCESS_CODE, "Request is done successfully"));
            manageNameIdResponse = SAMLSSOUtil.marshall(response);
        } catch (IdentityException e) {
           throw new RuntimeException("Error while building ManageNameIDResponse");
        }
        return manageNameIdResponse;
    }

}
