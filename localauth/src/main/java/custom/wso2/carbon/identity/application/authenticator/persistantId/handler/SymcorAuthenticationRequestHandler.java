package custom.wso2.carbon.identity.application.authenticator.persistantId.handler;

import custom.wso2.carbon.identity.application.authenticator.persistantId.SymcorAuthenticatorConstants;
import custom.wso2.carbon.identity.application.authenticator.persistantId.util.SymcorAuthenticatorUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SymcorAuthenticationRequestHandler extends DefaultAuthenticationRequestHandler{

    private static final Log log = LogFactory.getLog(SymcorAuthenticationRequestHandler.class);

    protected void sendResponse(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationContext context) throws FrameworkException {

        if (log.isDebugEnabled()) {
            StringBuilder debugMessage = new StringBuilder();
            debugMessage.append("Sending response back to: ");
            debugMessage.append(context.getCallerPath()).append("...\n");
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED).append(": ");
            debugMessage.append(String.valueOf(context.isRequestAuthenticated())).append("\n");
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED_USER).append(": ");
            if (context.getSequenceConfig().getAuthenticatedUser() != null) {
                debugMessage.append(context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier()).append("\n");
            } else {
                debugMessage.append("No Authenticated User").append("\n");
            }
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED_IDPS).append(": ");
            debugMessage.append(context.getSequenceConfig().getAuthenticatedIdPs()).append("\n");
            debugMessage.append(FrameworkConstants.SESSION_DATA_KEY).append(": ");
            debugMessage.append(context.getCallerSessionKey());

            log.debug(debugMessage);
        }

        // TODO rememberMe should be handled by a cookie authenticator. For now rememberMe flag that
        // was set in the login page will be sent as a query param to the calling servlet so it will
        // handle rememberMe as usual.
        String rememberMeParam = "";

        if (context.isRequestAuthenticated() && context.isRememberMe()) {
            rememberMeParam = rememberMeParam + "&chkRemember=on";
        }

        // redirect to the caller
        String redirectURL = context.getCallerPath() + "?sessionDataKey="
                + context.getCallerSessionKey() + rememberMeParam;

        if (context.getAuthenticationRequest().
                getRequestQueryParam(SymcorAuthenticatorConstants.HTTP_PARAM_SAML_NAMEID_REQUEST) != null) {
            String manageNameIdRequestId = null;
            try {
                manageNameIdRequestId = SymcorAuthenticatorUtil.getNameIDRequestId(context);
                redirectURL += "&"+SymcorAuthenticatorConstants.HTTP_PARAM_SAML_NAMEID_REQUEST_ID + "=" + manageNameIdRequestId;
            } catch (AuthenticationFailedException e) {
                throw new FrameworkException("Error while getting ManageNameIDRequest ID");
            }
        }

        try {
            response.sendRedirect(redirectURL);
        } catch (IOException e) {
            throw new FrameworkException(e.getMessage(), e);
        }
    }
}
