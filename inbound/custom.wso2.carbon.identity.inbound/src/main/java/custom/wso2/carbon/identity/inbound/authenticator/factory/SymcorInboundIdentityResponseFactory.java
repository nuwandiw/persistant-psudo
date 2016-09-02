package custom.wso2.carbon.identity.inbound.authenticator.factory;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundResponse;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymmetricEncrypter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;

import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
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
        builder.addParameter(SymcorInboundConstants.PLATFORM_INFO, getPlatformInfo(identityResponse));
        builder.addParameter(SymcorInboundConstants.USER_TOKEN, getEncryptedToken(identityResponse));
        builder.addParameter(SymcorInboundConstants.LANGUAGE, getLanguage(identityResponse));
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(getRedirectUrl(identityResponse));
        return builder;

    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {
        return null;
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
        String tenantDomain =
                ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject().getTenantDomain();
        Property[] props = getInboundAuthenticatorProperty(identityResponse, tenantDomain);
        for (Property prop : props) {
            if (prop.getName().equals(property)) {
                propertyValue = prop.getValue();
                break;
            }
        }
        return propertyValue;
    }

    private Property[] getInboundAuthenticatorProperty(IdentityResponse identityResponse, String tenantDomain) {
        String relyingParty = ((SymcorInboundResponse) identityResponse).getRelyingParty();
        Property[] properties = null;
        try {
            ServiceProvider sp =
                    ApplicationManagementServiceImpl.getInstance().getServiceProvider(relyingParty, tenantDomain);
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
        String platformInfo = getClaimValue(
                ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject(),
                SymcorInboundConstants.PLATFORM_INFO_CLAIM);
        if (platformInfo != null){
            return platformInfo;
        } else {
            return "";
        }
    }

    private String getLanguage(IdentityResponse identityResponse) {
        String language = getClaimValue(
                ((SymcorInboundResponse) identityResponse).getAuthenticationResult().getSubject(),
                SymcorInboundConstants.LANGUAGE_CLAIM);
        if (language != null){
            return language;
        } else {
            return "en";
        }
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
}
