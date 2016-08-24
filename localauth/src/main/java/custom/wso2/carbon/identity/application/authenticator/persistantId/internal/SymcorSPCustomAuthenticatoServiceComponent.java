package custom.wso2.carbon.identity.application.authenticator.persistantId.internal;

import custom.wso2.carbon.identity.application.authenticator.persistantId.SymcorSPCustomAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.application.authenticator.persistantId.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class SymcorSPCustomAuthenticatoServiceComponent {
    private static Log log = LogFactory.getLog(SymcorSPCustomAuthenticatoServiceComponent.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        SymcorSPCustomAuthenticatoServiceComponent.realmService = realmService;
    }

    protected void activate(ComponentContext ctxt) {
        try {
            SymcorSPCustomAuthenticator symcorAuth = new SymcorSPCustomAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), symcorAuth, null);
            if (log.isDebugEnabled()) {
                log.info("Symcor Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Symcor Authenticator bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("Symcor Authenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        SymcorSPCustomAuthenticatoServiceComponent.realmService = null;
    }
}
