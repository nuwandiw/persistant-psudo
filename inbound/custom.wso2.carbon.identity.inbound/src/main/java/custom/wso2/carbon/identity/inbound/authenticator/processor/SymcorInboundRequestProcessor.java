package custom.wso2.carbon.identity.inbound.authenticator.processor;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundResponse;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymcorInboundAuthConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;

import java.util.HashMap;


public class SymcorInboundRequestProcessor extends IdentityProcessor {

    private SymcorInboundAuthConfig symcorInboundAuthConfig = null;

    public SymcorInboundRequestProcessor(SymcorInboundAuthConfig symcorInboundAuthConfig){
        this.symcorInboundAuthConfig = symcorInboundAuthConfig;
    }



    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        FrameworkLoginResponse.FrameworkLoginResponseBuilder builder = null;

        IdentityMessageContext messageContext = new IdentityMessageContext(identityRequest,
                new HashMap<String, String>());

        if (identityRequest.getParameter("sessionDataKey") != null) {
            SymcorInboundResponse.SymcorInboundResponseBuilder respBuilder =
                    new SymcorInboundResponse.SymcorInboundResponseBuilder(messageContext);
            AuthenticationResult authenticationResult =
                    processResponseFromFrameworkLogin(messageContext, identityRequest);
            respBuilder.setAuthenticationResult(authenticationResult);
            respBuilder.setRelyingParty(getRelyingPartyId());
            respBuilder.setAuthType(getName());
            String requestId = identityRequest.getParameter(SymcorInboundConstants.HTTP_PARAM_SAML_NAMEID_REQUEST_ID);
            if (requestId != null) {
                respBuilder.setRequestId(requestId);
            }
            return respBuilder;
        } else {
            return buildResponseForFrameworkLogin(messageContext);
        }
    }

    @Override
    public String getCallbackPath(IdentityMessageContext identityMessageContext) {
        return "/identity"; //TODO check this
    }

    @Override
    public String getRelyingPartyId() {
        return "symcor";
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return true;
    }

    @Override
    public String getName(){
        return "symcor-inbound-type";
    }

}
