package custom.wso2.carbon.identity.application.authenticator.persistantId.handler;

import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.claims.ClaimHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.claims.impl.DefaultClaimHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class SymcorClaimHandler extends DefaultClaimHandler implements ClaimHandler {

    @Override
    protected Map<String, String> handleLocalClaims(String spStandardDialect,
                                                    StepConfig stepConfig,
                                                    AuthenticationContext context)
            throws FrameworkException {
        AuthenticatedUser authenticatedUser = stepConfig.getAuthenticatedUser();
        Map<String, String> symcorRequestedClaims = new HashMap<>();

        Map<ClaimMapping, String> authenticatedUserAttributes = authenticatedUser.getUserAttributes();
        Iterator it = authenticatedUserAttributes.entrySet().iterator();
        while (it.hasNext()){
            Map.Entry pair = (Map.Entry)it.next();
            ClaimMapping claim = (ClaimMapping)pair.getKey();
            String claimUrl = claim.getLocalClaim().getClaimUri();
            symcorRequestedClaims.put(claimUrl, (String) pair.getValue());
        }
        return symcorRequestedClaims;
    }
}
