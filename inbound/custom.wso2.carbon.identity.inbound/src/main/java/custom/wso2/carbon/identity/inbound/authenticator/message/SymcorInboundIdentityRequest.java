package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class SymcorInboundIdentityRequest extends IdentityRequest {

    private String samlresponse;
    private String spEntityId;

    protected SymcorInboundIdentityRequest(SymcorIdentityRequestBuilder builder) {
        super(builder);
        this.samlresponse = builder.samlResponse;
        this.spEntityId = builder.spEntityId;
    }

    public String getSamlresponse() {
        return samlresponse;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public static class SymcorIdentityRequestBuilder extends IdentityRequestBuilder {

        private String samlResponse;
        private String spEntityId;

        public SymcorIdentityRequestBuilder(){
        }

        public SymcorIdentityRequestBuilder(HttpServletRequest request, HttpServletResponse response){
            super(request, response);
        }

        @Override
        public SymcorInboundIdentityRequest build() {
            return new SymcorInboundIdentityRequest(this);
        }

        public SymcorIdentityRequestBuilder setSamlResponse(String samlResponse) {
            this.samlResponse = samlResponse;
            return this;
        }

        public SymcorIdentityRequestBuilder setSpEntityId(String spEntityId) {
            this.spEntityId = spEntityId;
            return this;
        }

    }
}
