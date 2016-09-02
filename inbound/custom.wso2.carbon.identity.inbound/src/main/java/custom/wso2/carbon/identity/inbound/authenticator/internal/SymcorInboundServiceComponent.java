package custom.wso2.carbon.identity.inbound.authenticator.internal;


import custom.wso2.carbon.identity.inbound.authenticator.factory.SymcorInboundIdentityResponseFactory;
import custom.wso2.carbon.identity.inbound.authenticator.processor.SymcorInboundRequestProcessor;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymcorInboundAuthConfig;
import custom.wso2.carbon.identity.inbound.authenticator.util.SymcorInboundUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Hashtable;

/**
 * @scr.component name="custom.wso2.carbon.identity.inbound.authenticator.internal" immediate="true"
 * @scr.reference name="registry.service" interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService" unbind="unsetRegistryService"
 * @scr.reference name="config.context.service" immediate="true"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="1..1" policy="dynamic"
 * bind="setConfigurationContextService" unbind="unsetConfigurationContextService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService" cardinality="1..1"
 * policy="dynamic" bind="setHttpService" unbind="unsetHttpService"
 */
public class SymcorInboundServiceComponent {

    private static Log log = LogFactory.getLog(SymcorInboundServiceComponent.class);

    protected void activate(ComponentContext ctxt){

        try {
            SymcorInboundAuthConfig symcorInboundAuthConfig = new SymcorInboundAuthConfig();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class,
                    symcorInboundAuthConfig, props);

            ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(),
                    new SymcorInboundRequestProcessor(symcorInboundAuthConfig), null);

            ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                    new SymcorInboundIdentityResponseFactory(), null);
        } catch (Exception e) {
            log.error("Error Activating Symcor Inbound Auth Package");
            throw new RuntimeException(e);
        }

    }

    protected void deactivate(ComponentContext ctxt) {
        SymcorInboundUtil.setBundleContext(null);
        if (log.isDebugEnabled()) {
            log.info("Symcor inbound authenticator bundle is deactivated");
        }
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Symcor inbound authenticator bundle");
        }
        try {
            SymcorInboundUtil.setRegistryService(registryService);
        } catch (Throwable e) {
            log.error("Failed to get a reference to the Registry in Symcor inbound authenticator bundle", e);
        }
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setRegistryService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setConfigCtxService(null);
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the Symcor inbound authenticator bundle");
        }
        SymcorInboundUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the Symcor inbound authenticator bundle");
        }

        SymcorInboundUtil.setHttpService(null);
    }
}
