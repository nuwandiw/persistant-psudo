package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SymcorInboundRequest extends IdentityRequest{

    private String spEntityID;

    protected SymcorInboundRequest(IdentityRequestBuilder builder) {
        super(builder);
        this.spEntityID = ((SymcorInboundRequestBuilder) builder).spEntityID;
    }

    public String getSpEntityID(){
        return spEntityID;
    }

    public static class SymcorInboundRequestBuilder extends IdentityRequestBuilder{

        private String spEntityID;

        public SymcorInboundRequestBuilder (HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        @Override
        public SymcorInboundRequest build() {
            return new SymcorInboundRequest(this);
        }

        public SymcorInboundRequestBuilder setSpEntityID(String spEntityID) {
            this.spEntityID = spEntityID;
            return this;
        }
    }
}
