package custom.wso2.carbon.identity.inbound.authenticator.factory;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SymcorInboundRequestFactory extends HttpIdentityRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        boolean canHandleRequest = false;
        if (request.getParameter(SymcorInboundConstants.SP_ENTITY_ID) != null) {
            if (request.getParameter(SymcorInboundConstants.HTTP_PARAM_SAML_NAMEID_REQUEST) == null) {
                canHandleRequest = true;
            }
        }
        return canHandleRequest;
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
