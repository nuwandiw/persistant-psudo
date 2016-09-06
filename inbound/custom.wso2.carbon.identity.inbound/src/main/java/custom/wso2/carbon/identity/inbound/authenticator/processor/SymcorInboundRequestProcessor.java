package custom.wso2.carbon.identity.inbound.authenticator.processor;

import custom.wso2.carbon.identity.inbound.authenticator.SymcorInboundConstants;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundRequest;
import custom.wso2.carbon.identity.inbound.authenticator.message.SymcorInboundResponse;
import custom.wso2.carbon.identity.inbound.authenticator.util.SAMLNameIdUtil;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymcorInboundAuthConfig;
import org.opensaml.saml2.core.ManageNameIDRequest;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


public class SymcorInboundRequestProcessor extends IdentityProcessor {

    private SymcorInboundAuthConfig symcorInboundAuthConfig = null;

    public SymcorInboundRequestProcessor(SymcorInboundAuthConfig symcorInboundAuthConfig){
        this.symcorInboundAuthConfig = symcorInboundAuthConfig;
    }

    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        IdentityMessageContext messageContext = new IdentityMessageContext(identityRequest,
                new HashMap<String, String>());
        SymcorInboundResponse.SymcorInboundResponseBuilder respBuilder =
                new SymcorInboundResponse.SymcorInboundResponseBuilder(messageContext);

        String sessionId = identityRequest.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        String nameIdRequest = identityRequest.getParameter(SymcorInboundConstants.HTTP_PARAM_SAML_NAMEID_REQUEST);

        respBuilder.setRelyingParty(getRelyingPartyId());
        respBuilder.setAuthType(getName());
        respBuilder.setTenanDomain(identityRequest.getTenantDomain());

        if (sessionId != null) {
            AuthenticationResult authenticationResult =
                    processResponseFromFrameworkLogin(messageContext, identityRequest);
            respBuilder.setAuthenticationResult(authenticationResult);
            return respBuilder;
        } else if (nameIdRequest != null) {
            try {
                ManageNameIDRequest request = SAMLNameIdUtil.getNameIDRequestObject(nameIdRequest);
                respBuilder.setNameIdRequest(request);
                return respBuilder;
            } catch (AuthenticationFailedException e) {
                throw new FrameworkException("Error while processing ManageNameIDRequest");
            }
        }
        else {
            try {
                SymcorInboundRequest symcorInboundRequest = (SymcorInboundRequest) identityRequest;
                sendRequestToFramework(symcorInboundRequest);
            } catch (ServletException e) {
                throw new FrameworkException("Error while processing authentication request");
            } catch (IOException e) {
                throw new FrameworkException("Error while processing authentication request");
            }
            return buildResponseForFrameworkLogin(messageContext);
        }
    }

    private void sendRequestToFramework(SymcorInboundRequest request) throws ServletException, IOException {

        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request.getRequest());


        String sessionDataKeyValue = null ;
        if((sessionDataKeyValue = request.getParameter(FrameworkConstants.SESSION_DATA_KEY)) == null){
            sessionDataKeyValue = UUID.randomUUID().toString();
            requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKeyValue);
        }
        Map<String, String[]> parameterMap = request.getRequest().getParameterMap();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        for (Object entry : request.getHeaderMap().keySet()) {
            authenticationRequest.addHeader((String) entry, request.getHeaderMap().get(entry));
        }
        authenticationRequest.setRelyingParty(getRelyingPartyId());
        authenticationRequest.setType(getName());
        authenticationRequest.setPassiveAuth(false);
        authenticationRequest.setForceAuth(false);
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode("/identity/symcorAuth",
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path " +
                    "/identity/symcorAuth", e);
        }

        requestWrapper.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST,
                new AuthenticationRequestCacheEntry(authenticationRequest));
        requestWrapper.setParameter(SymcorInboundConstants.SAML_RESPONSE,
                request.getRequest().getParameter(SymcorInboundConstants.SAML_RESPONSE));
        requestWrapper.setParameter("type", getName());

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(request.getResponse());
        commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

    }

    @Override
    public String getCallbackPath(IdentityMessageContext identityMessageContext) {
        return "/identity/symcorAuth"; //TODO check this
    }

    @Override
    public String getRelyingPartyId() {
        return "symcor";
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return true;
    }

    @Override
    public String getName(){
        return "symcor-inbound-type";
    }

}
