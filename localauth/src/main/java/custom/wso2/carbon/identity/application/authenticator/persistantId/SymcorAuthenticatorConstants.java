package custom.wso2.carbon.identity.application.authenticator.persistantId;

/**
 * Created by nuwandi on 8/16/16.
 */
public class SymcorAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "SymcorAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "symcor";
    public static final String CMS_AUTHENTICATION_ENDPOINT = "CMSAuthenticationEndpoint";
    public static final String IDP_URL = "IDPUrl";
    public static final String HTTP_PARAM_SAML_NAMEID_REQUEST = "SAMLRequest";

    public static final int PLATFORM_INFO_WLBX = 1;
    public static final int PLATFORM_INFO_CMS = 0;
    public static final int PLATFORM_INFO_BOTH = 2;

    public static final String PLATFORM_INFO_CLAIM = "http://wso2.org/claims/platformInfo";
    public static final String LANGUAGE_CLAIM = "http://wso2.org/claims/locality";

    public static final String LANGUAGE = "language";

    public class CMSAuthenticator {
        public static final String USER_ID = "userID";
        public static final String PASSWORD = "password";
        public static final String ACCEPT_HEADER = "Accept";
        public static final String HEADER_JSON = "application/json";
        public static final String CMS_ARCHIVE = "CMS-Web-archive";
        public static final String CMS_AUTH_RESULT = "AuthenticationResult";
        public static final String PASSED = "passed";
    }
}
