package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;

public class SymcorInboundResponse extends FrameworkLoginResponse {

    private AuthenticationResult authenticationResult;
    private String requestId;

    protected SymcorInboundResponse(FrameworkLoginResponseBuilder builder) {
        super(builder);
        this.authenticationResult = ((SymcorInboundResponseBuilder) builder).authenticationResult;
        this.requestId = ((SymcorInboundResponseBuilder) builder).requestId;
    }

    public AuthenticationResult getAuthenticationResult() {
        return authenticationResult;
    }

    public String getRequestId(){
        return requestId;
    }


    public static class SymcorInboundResponseBuilder extends FrameworkLoginResponseBuilder {

        private AuthenticationResult authenticationResult;
        private String requestId;

        public SymcorInboundResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SymcorInboundResponseBuilder setAuthenticationResult(AuthenticationResult authenticationResult) {
            this.authenticationResult = authenticationResult;
            return this;
        }

        public SymcorInboundResponseBuilder setRequestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public SymcorInboundResponse build() {
            return new SymcorInboundResponse(this);
        }
    }
}
