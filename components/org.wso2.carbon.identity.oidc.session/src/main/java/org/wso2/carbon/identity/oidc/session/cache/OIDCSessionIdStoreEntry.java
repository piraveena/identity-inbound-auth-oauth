package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.CacheEntry;

/**
 * This class holds opbscookie id required for session termination event and cached against session identifier.
 */
public class OIDCSessionIdStoreEntry extends CacheEntry {

    private static final long serialVersionUID = -4123547630178387314L;
    private String opbsCookieId;

    public String getopbsCookieId() {

        return opbsCookieId;
    }

    public void setOpbsCookieId(String opbsCookieId) {

        this.opbsCookieId = opbsCookieId;
    }
}
