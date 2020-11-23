package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.CacheKey;

/**
 * This class holds the cache key which is the sessionIdentifier related to the framework session. This will be the
 * hash of commonAuthId cookie value.
 */
public class OIDCSessionIdStoreKey extends CacheKey {

    private static final long serialVersionUID = -3480330645196653791L;

    private String sessionIdentifier;

    public OIDCSessionIdStoreKey(String sessionIdentifier) {

        this.sessionIdentifier = sessionIdentifier;
    }

    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        OIDCSessionIdStoreKey other = (OIDCSessionIdStoreKey) obj;
        if (sessionIdentifier == null) {
            if (other.sessionIdentifier != null) {
                return false;
            }
        } else if (!sessionIdentifier.equals(other.sessionIdentifier)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {

        final int prime = 31;
        int result = 1;
        result = prime * result + ((sessionIdentifier == null) ? 0 : sessionIdentifier.hashCode());
        return result;
    }

    public String getSessionIdentifier() {

        return sessionIdentifier;
    }

    public void setSessionIdentifier(String sessionIdentifier) {

        this.sessionIdentifier = sessionIdentifier;
    }
}
