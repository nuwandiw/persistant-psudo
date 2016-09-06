package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SymcorInboundRequest extends IdentityRequest{

    private HttpServletRequest request;
    private HttpServletResponse response;

    protected SymcorInboundRequest(IdentityRequestBuilder builder) {
        super(builder);
        this.request = ((SymcorInboundRequestBuilder) builder).request;
        this.response = ((SymcorInboundRequestBuilder) builder).response;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public static class SymcorInboundRequestBuilder extends IdentityRequestBuilder{
        private HttpServletRequest request;
        private HttpServletResponse response;

        public SymcorInboundRequestBuilder (HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        @Override
        public SymcorInboundRequest build() {
            return new SymcorInboundRequest(this);
        }

        public SymcorInboundRequestBuilder setRequest(HttpServletRequest request) {
            this.request = request;
            return this;
        }

        public SymcorInboundRequestBuilder setResponse(HttpServletResponse response){
            this.response = response;
            return this;
        }
    }
}
