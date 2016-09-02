package custom.wso2.carbon.identity.inbound.authenticator;

import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;

/**
 * Created by nuwandi on 8/28/16.
 */
public class SymcorInboundConstants {
//     public static final String SP_ENTITY_ID = "spEntityID";
     public static final String SAML_RESPONSE = "SAMLResponse";
    public static final String SP_ENTITY_ID = "SAMLRequest"; //temp
    public static final String LANGUAGE = "language";
    public static final String PLATFORM_INFO = "platform";
    public static final String USER_TOKEN = "usertoken";

    public static final String PLATFORM_INFO_CLAIM = "http://wso2.org/claims/platformInfo";
    public static final String LANGUAGE_CLAIM = "http://wso2.org/claims/locality";

    public static final String OLD_PLATFORM_PROPERTY = "old-platform";
    public static final String NEW_PLATFORM_PROPERTY = "new-platform";

    public static final String SYMMETRIC_KEY_FILE_PATH = CarbonUtils.getCarbonHome() + File.separator + "repository" +
            File.separator + "resources" + File.separator + "security" + File.separator + "symmetric-key.properties";
}
