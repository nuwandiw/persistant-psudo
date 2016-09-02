package custom.wso2.carbon.identity.inbound.authenticator.factory;


import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundIdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SymcorInboundIdentityRequestFactory extends HttpIdentityRequestFactory{

    public String getName() {
        return "SymcorInboundIdentityRequestFactory";
    }

    //Modify this to ensure that we have the right selection criterion for this Inbound Authenticator
    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
//        if (request.getParameter(SymcorInboundConstants.SP_ENTITY_ID) != null &&
//                request.getParameter(SymcorInboundConstants.SAML_RESPONSE) == null) {
//            return true;
//        }
        return false;
    }

    @Override
    public SymcorInboundIdentityRequest.SymcorIdentityRequestBuilder create(HttpServletRequest request,
                                                                            HttpServletResponse response) {

        SymcorInboundIdentityRequest.SymcorIdentityRequestBuilder builder =
                new SymcorInboundIdentityRequest.SymcorIdentityRequestBuilder(request, response);

        builder.setQueryString(request.getQueryString());
        builder.setSamlResponse(request.getParameter(SymcorInboundConstants.SAML_RESPONSE));
        builder.setSpEntityId(request.getParameter(SymcorInboundConstants.SP_ENTITY_ID));
        return builder;
    }
}
