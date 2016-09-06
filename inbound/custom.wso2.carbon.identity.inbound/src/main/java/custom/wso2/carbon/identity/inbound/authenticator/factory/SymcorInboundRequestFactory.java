package custom.wso2.carbon.identity.inbound.authenticator.factory;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SymcorInboundRequestFactory extends HttpIdentityRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if (request.getParameter(SymcorInboundConstants.SAML_RESPONSE) != null ||
                request.getParameter(SymcorInboundConstants.SP_ENTITY_ID) != null) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public SymcorInboundRequest.SymcorInboundRequestBuilder create(HttpServletRequest request, HttpServletResponse response){
        SymcorInboundRequest.SymcorInboundRequestBuilder builder =
                new SymcorInboundRequest.SymcorInboundRequestBuilder(request, response);
        builder.setRequest(request);
        builder.setResponse(response);
        return builder;
    }
}
