package custom.wso2.carbon.identity.application.authenticator.persistantId;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.SAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SymcorSPCustomAuthenticator extends BasicAuthenticator{

    private static final Log log = LogFactory.getLog(SymcorSPCustomAuthenticator.class);
    private String cmsAuthEndpoint;
    private String IdpUrl;

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String SAMLResponse = request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_RESP);
        String SAMLRequest = request.getParameter(SymcorAuthenticatorConstants.HTTP_PARAM_SAML_NAMEID_REQUEST);
        if (SAMLResponse != null || SAMLRequest != null) {
            return true;
        } else {
            return super.canHandle(request);
        }
    }

    private void initCMSAuthEndpoint() throws AuthenticationFailedException {
        this.cmsAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(
                SymcorAuthenticatorConstants.CMS_AUTHENTICATION_ENDPOINT);
        if (StringUtils.isBlank(this.cmsAuthEndpoint)) {
            log.error("CMS authentication endpoint not configured");
            throw new AuthenticationFailedException("CMS authentication endpoint not configured");
        }
    }

    private void initIDPUrl() throws AuthenticationFailedException {
        this.IdpUrl = getAuthenticatorConfig().getParameterMap().get(SymcorAuthenticatorConstants.IDP_URL);
        if (StringUtils.isBlank(this.IdpUrl)){
            log.error("IDP URL not configured for the authenticator");
            throw new AuthenticationFailedException("IDP URL not configured for the authenticator");
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        AuthenticatedUser localUser = context.getSubject();
        String SAMLResponse = request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_RESP);
        String localUserID;
        SymcorSPAuthenticatorDAO dao;

        if (canHandle(request)) {
            if (SAMLResponse != null) {
                Map<String, String> claims = new HashMap<>();
                String nameID = getNameIDFromSAML(request, context);
                dao = new SymcorSPAuthenticatorDAO();

                try {
                    if (localUser != null) { //previously locally authenticated user
                        localUserID = localUser.getUserName();
                        dao.linkNameIDToUser(localUserID, nameID);
                    } else { //saml response for idp authenticated user
                        localUserID = dao.getUsernameForNameID(nameID);
                        if (localUserID == null) {
                            throw new AuthenticationFailedException("No record in SP DB for the NameID : " + nameID);
                        }
                    }
                    claims.put(SymcorAuthenticatorConstants.PLATFORM_INFO_CLAIM,
                            String.valueOf(dao.getPlatformInfo(localUserID)));
                    claims.put(SymcorAuthenticatorConstants.LANGUAGE_CLAIM,
                            request.getParameter(SymcorAuthenticatorConstants.LANGUAGE));
                    updateContextWithLocalUser(context, localUserID, claims);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                } catch (SQLException e) {
                    throw new AuthenticationFailedException(e.getMessage());
                }
            } else { //request with username/password
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }else {
            return super.process(request, response, context);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);
        int platformInfo;

        boolean isAuthenticated = false;

        SymcorSPAuthenticatorDAO dao = new SymcorSPAuthenticatorDAO();
        try {
            platformInfo = dao.getPlatformInfo(username);
        } catch (SQLException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }

        if (SymcorAuthenticatorConstants.PLATFORM_INFO_WLBX == platformInfo) {
            //TODO:Authenticate against SSO_SP_USER
        } else if (SymcorAuthenticatorConstants.PLATFORM_INFO_BOTH == platformInfo ||
                SymcorAuthenticatorConstants.PLATFORM_INFO_CMS == platformInfo) {
            isAuthenticated = isAuthenticatedFromCMS(username, password);
        }

        if (isAuthenticated) {
            String ssoUrl = "";
            IdentityProvider idp = getAuthenticatorFederatedIdp(context);

            try {
                SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
                saml2SSOManager.init(context.getTenantDomain(), getAuthenticatorConfig().getParameterMap(),
                        idp);
                ssoUrl = saml2SSOManager.buildRequest(request, false, false, getAuthenticatorFederatedUrl(idp), context);
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                response.sendRedirect(ssoUrl);

            } catch (SAMLSSOException e) {
                throw new AuthenticationFailedException("Error while building SAML Request");
            } catch (IOException e) {
                throw new AuthenticationFailedException("Error while redirecting to " + ssoUrl);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }

            throw new InvalidCredentialsException("User authentication failed due to invalid credentials");
        }
    }

    protected AuthenticatorConfig getAuthenticatorConfig() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(getName());
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<String, String>());
        }
        return authConfig;
    }

    protected String getCMSEndpoint() throws AuthenticationFailedException {
        if(StringUtils.isBlank(cmsAuthEndpoint)){
            initCMSAuthEndpoint();
        }
        return this.cmsAuthEndpoint;
    }

    protected String getIDPUrl() throws AuthenticationFailedException {
        if (StringUtils.isBlank(IdpUrl)){
            initIDPUrl();
        }
        return this.IdpUrl;
    }

    private SAML2SSOManager getSAML2SSOManagerInstance() throws SAMLSSOException {

        String managerClassName = getAuthenticatorConfig().getParameterMap()
                .get(SSOConstants.ServerConfig.SAML2_SSO_MANAGER);
        if (managerClassName != null) {
            try {
                Class clazz = Class.forName(managerClassName);
                return (SAML2SSOManager) clazz.newInstance();
            } catch (ClassNotFoundException e) {
                throw new SAMLSSOException(e.getMessage(), e);
            } catch (InstantiationException e) {
                throw new SAMLSSOException(e.getMessage(), e);
            } catch (IllegalAccessException e) {
                throw new SAMLSSOException(e.getMessage(), e);
            }
        } else {
            return new DefaultSAML2SSOManager();
        }
    }

    private boolean isAuthenticatedFromCMS(String username, String password)
            throws AuthenticationFailedException {

        boolean isAuthenticated = false;
        String cmsAuthEndpoint = getCMSEndpoint();
        HttpClient client = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(cmsAuthEndpoint);

        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair(SymcorAuthenticatorConstants.CMSAuthenticator.USER_ID, username));
        parameters.add(new BasicNameValuePair(SymcorAuthenticatorConstants.CMSAuthenticator.PASSWORD, password));

        try {
            post.setHeader(SymcorAuthenticatorConstants.CMSAuthenticator.ACCEPT_HEADER,
                    SymcorAuthenticatorConstants.CMSAuthenticator.HEADER_JSON);
            post.setEntity(new UrlEncodedFormEntity(parameters));
//            HttpResponse CMSResponse = client.execute(post);
//
//            String result = EntityUtils.toString(CMSResponse.getEntity());

            //---------------- hard coding result for testing --------------------
            String result = "[{\"CMS-Web-archive\": {\"AuthenticationResult\": \"passed\"}}]";
            //--------------------------------------------------------------------
            JSONArray resultArray = new JSONArray(result);
            JSONObject resultObject = resultArray.getJSONObject(0);

            String authenticationResult =
                    resultObject.getJSONObject(SymcorAuthenticatorConstants.CMSAuthenticator.CMS_ARCHIVE)
                            .getString(SymcorAuthenticatorConstants.CMSAuthenticator.CMS_AUTH_RESULT);
            if (SymcorAuthenticatorConstants.CMSAuthenticator.PASSED.equals(authenticationResult)) {
                isAuthenticated = true;
            }

        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }
//        catch (ClientProtocolException e) {
//            throw new AuthenticationFailedException(e.getMessage());
//        }
        catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage());
        } catch (JSONException e) {
            throw new AuthenticationFailedException(e.getMessage());
        }

        return isAuthenticated;
    }

    private String getNameIDFromSAML (HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {
        String subject = null;
        try {
            SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
            saml2SSOManager.init(context.getTenantDomain(), getAuthenticatorConfig().getParameterMap(),
                    getAuthenticatorFederatedIdp(context));
            saml2SSOManager.processResponse(request);
            subject = (String) request.getSession().getAttribute("username"); //nameID is set as username
            if (subject == null) {
                throw new AuthenticationFailedException("Cannot find name ID in the SAMLResponse");
            }
        } catch (SAMLSSOException e) {
            throw new AuthenticationFailedException("Error while initiating SAML2SSOManager");
        }
        return  subject;
    }


    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String identifier = request.getParameter("sessionDataKey");

        if (identifier == null) {
            identifier = request.getParameter("RelayState");

            if (identifier != null) {
                try {
                    return URLDecoder.decode(identifier, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    log.error("Exception while URL decoding the Relay State", e);
                }
            }
        }

        return identifier;
    }

    private IdentityProvider getAuthenticatorFederatedIdp(AuthenticationContext context)
            throws AuthenticationFailedException {

        String idp = getIDPUrl();
        IdentityProvider identityProvider;
        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(idp, context.getTenantDomain());

        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException("Error while getting federated Idp for name : " + idp);
        }
        return identityProvider;
    }

    private String getAuthenticatorFederatedUrl(IdentityProvider identityProvider)
            throws AuthenticationFailedException {
        String ssoUrl = null;
        Property[] props = identityProvider.getDefaultAuthenticatorConfig().getProperties();

        for (Property idpProperty : props) {
            if("SSOUrl".equals(idpProperty.getName())) {
                ssoUrl = idpProperty.getValue();
            }
        }

        if (ssoUrl == null) {
            throw new AuthenticationFailedException("No sso url found in the Idp");
        }
        return ssoUrl;
    }

    private void updateContextWithLocalUser(AuthenticationContext context, String userName, Map<String, String> claims) {
        AuthenticatedUser user = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName);
        user.setUserAttributes(FrameworkUtils.buildClaimMappings(claims));
        context.setSubject(user);
    }

    @Override
    public String getFriendlyName() {
        return SymcorAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return SymcorAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
