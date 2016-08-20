package custom.wso2.carbon.identity.application.authenticator.persistantId;

/**
 * Created by nuwandi on 8/16/16.
 */
public class SQLQueries {
    public static final String GET_PLATFORM_INFO = "SELECT PLATFORM_INFO FROM SSO_SP_USER WHERE LOGIN_NAME=?";
    public static final String GET_USERNAME_FOR_NAMEID = "SELECT LOGIN_NAME FROM SSO_SP_USER WHERE SAML2_NAMEID_INFOKEY=?";
    public static final String LINK_NAMEID_TO_USER = "UPDATE SSO_SP_USER SET SAML2_NAMEID_INFOKEY=? WHERE LOGIN_NAME=?";
}
