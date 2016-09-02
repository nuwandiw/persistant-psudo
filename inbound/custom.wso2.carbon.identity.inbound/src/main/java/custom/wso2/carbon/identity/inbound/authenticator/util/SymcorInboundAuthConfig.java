package custom.wso2.carbon.identity.inbound.authenticator.util;

import org.wso2.carbon.identity.application.common.model.InboundProvisioningConnector;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;


public class SymcorInboundAuthConfig extends AbstractInboundAuthenticatorConfig
        implements InboundProvisioningConnector{

    private static final String NAME = "symcor-inbound-type";

    public SymcorInboundAuthConfig(){

    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getConfigName() {
        return NAME;
    }

    @Override
    public String getFriendlyName() {
        return "Symcor Inbound Configuration";
    }

    @Override
    public String getRelyingPartyKey() {
        return "symcor-inbound";
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property oldPlatformUrl = new Property();
        oldPlatformUrl.setName("old-platform");
        oldPlatformUrl.setDisplayName("WLBX URL");

        Property newPlatformUrl = new Property();
        newPlatformUrl.setName("new-platform");
        newPlatformUrl.setDisplayName("CMS URL");

        Property appType = new Property();
        appType.setName("appType");
        appType.setValue(getConfigName());
        appType.setDisplayName("UI Config Type");

        return new Property[]{oldPlatformUrl, newPlatformUrl, appType};
    }
}
