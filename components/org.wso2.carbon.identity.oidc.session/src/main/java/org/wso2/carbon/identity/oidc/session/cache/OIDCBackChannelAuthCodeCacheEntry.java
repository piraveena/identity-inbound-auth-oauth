package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.CacheEntry;

/**
 * This class holds sessionID required for Authorization code flow in OIDCBackChannel logout and gets cahched againts
 * Authorizarion code
 */
public class OIDCBackChannelAuthCodeCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -4123547630178387354L;

    private String sessionId;

    /**
     * @param sessionId
     */
    public void setSessionId(String sessionId) {

        this.sessionId = sessionId;
    }

    /**
     * @return sessionId (sid Cliam) for OIDCBackChannel Logout
     */
    public String getSessionId() {

        return sessionId;
    }
}
