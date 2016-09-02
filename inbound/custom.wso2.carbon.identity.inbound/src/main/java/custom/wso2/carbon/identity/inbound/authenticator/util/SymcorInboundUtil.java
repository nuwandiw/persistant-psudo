package custom.wso2.carbon.identity.inbound.authenticator.util;

import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

public class SymcorInboundUtil {

    private static RegistryService registryService;
    private static BundleContext bundleContext;
    private static RealmService realmService;
    private static ConfigurationContextService configCtxService;
    private static HttpService httpService;

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static BundleContext getBundleContext() {
        return bundleContext;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    public static ConfigurationContextService getConfigCtxService() {
        return configCtxService;
    }

    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setBundleContext(BundleContext bundleContext) {
        SymcorInboundUtil.bundleContext = bundleContext;

    }

    public static void setRegistryService(RegistryService registryService) {
        SymcorInboundUtil.registryService = registryService;

    }

    public static void setRealmService(RealmService realmService) {
        SymcorInboundUtil.realmService = realmService;

    }

    public static void setConfigCtxService(ConfigurationContextService configCtxService) {
        SymcorInboundUtil.configCtxService = configCtxService;
    }

    public static void setHttpService(HttpService httpService) {
        SymcorInboundUtil.httpService = httpService;
    }
}
