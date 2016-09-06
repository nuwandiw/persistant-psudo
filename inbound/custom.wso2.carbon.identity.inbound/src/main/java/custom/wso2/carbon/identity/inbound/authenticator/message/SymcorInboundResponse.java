package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.opensaml.saml2.core.ManageNameIDRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;

public class SymcorInboundResponse extends FrameworkLoginResponse {

    private AuthenticationResult authenticationResult;
    private ManageNameIDRequest nameIdRequest;
    private String tenantDomain;

    protected SymcorInboundResponse(FrameworkLoginResponseBuilder builder) {
        super(builder);
        this.authenticationResult = ((SymcorInboundResponseBuilder) builder).authenticationResult;
        this.nameIdRequest = ((SymcorInboundResponseBuilder) builder).nameIdRequest;
        this.tenantDomain = ((SymcorInboundResponseBuilder) builder).tenantDomain;
    }

    public AuthenticationResult getAuthenticationResult() {
        return authenticationResult;
    }

    public ManageNameIDRequest getNameIdRequest(){
        return nameIdRequest;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public static class SymcorInboundResponseBuilder extends FrameworkLoginResponseBuilder {

        private AuthenticationResult authenticationResult;
        private ManageNameIDRequest nameIdRequest;
        private String tenantDomain;

        public SymcorInboundResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SymcorInboundResponseBuilder setAuthenticationResult(AuthenticationResult authenticationResult) {
            this.authenticationResult = authenticationResult;
            return this;
        }

        public SymcorInboundResponseBuilder setNameIdRequest(ManageNameIDRequest nameIdRequest) {
            this.nameIdRequest = nameIdRequest;
            return this;
        }

        public SymcorInboundResponseBuilder setTenanDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        public SymcorInboundResponse build() {
            return new SymcorInboundResponse(this);
        }
    }
}
