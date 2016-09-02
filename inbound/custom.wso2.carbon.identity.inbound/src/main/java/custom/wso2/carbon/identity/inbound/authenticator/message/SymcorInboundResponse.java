package custom.wso2.carbon.identity.inbound.authenticator.message;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;

public class SymcorInboundResponse extends FrameworkLoginResponse {

    private String oldPlatform;
    private String newPlatform;
    private AuthenticationResult authenticationResult;
    private String language;

    protected SymcorInboundResponse(FrameworkLoginResponseBuilder builder) {
        super(builder);
        this.oldPlatform = ((SymcorInboundResponseBuilder) builder).oldPlatform;
        this.newPlatform = ((SymcorInboundResponseBuilder) builder).newPlatform;
        this.authenticationResult = ((SymcorInboundResponseBuilder) builder).authenticationResult;
        this.language = ((SymcorInboundResponseBuilder) builder).language;
    }

    public String getOldPlatform() {
        return oldPlatform;
    }

    public String getNewPlatform() {
        return newPlatform;
    }

    public AuthenticationResult getAuthenticationResult() {
        return authenticationResult;
    }

    public String getLanguage() {
        return language;
    }

    public static class SymcorInboundResponseBuilder extends FrameworkLoginResponseBuilder {

        private String oldPlatform;
        private String newPlatform;
        private AuthenticationResult authenticationResult;
        private String language;

        public SymcorInboundResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SymcorInboundResponseBuilder setOldPlatform(String oldPlatform) {
            this.oldPlatform = oldPlatform;
            return this;
        }

        public SymcorInboundResponseBuilder setNewPlatform(String newPlatform) {
            this.newPlatform = newPlatform;
            return this;
        }

        public SymcorInboundResponseBuilder setAuthenticationResult(AuthenticationResult authenticationResult) {
            this.authenticationResult = authenticationResult;
            return this;
        }

        public SymcorInboundResponseBuilder setLanguage(String language) {
            this.language = language;
            return this;
        }


        public SymcorInboundResponse build() {
            return new SymcorInboundResponse(this);
        }
    }
}
