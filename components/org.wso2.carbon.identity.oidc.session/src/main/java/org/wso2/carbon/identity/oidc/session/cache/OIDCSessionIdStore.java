package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * Caches SessionIdentifier against the opbs cookie value.
 */
public class OIDCSessionIdStore extends BaseCache<OIDCSessionIdStoreKey, OIDCSessionIdStoreEntry> {

    private static final String CACHE_NAME = "OIDCSessionIdStore";
    private static volatile OIDCSessionIdStore instance;

    public OIDCSessionIdStore() {

        super(CACHE_NAME);
    }

    public static OIDCSessionIdStore getInstance() {

        if (instance == null) {
            synchronized (OIDCSessionIdStore.class) {
                if (instance == null) {
                    instance = new OIDCSessionIdStore();
                }
            }
        }
        return instance;
    }

    public void addToCache(OIDCSessionIdStoreKey key, OIDCSessionIdStoreEntry entry) {

        super.addToCache(key, entry);
        SessionDataStore.getInstance().storeSessionData(key.getSessionIdentifier(), CACHE_NAME, entry);
    }

    public OIDCSessionIdStoreEntry getValueFromCache(OIDCSessionIdStoreKey key) {

        OIDCSessionIdStoreEntry cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry =
                    (OIDCSessionIdStoreEntry) SessionDataStore.getInstance().getSessionData(key.getSessionIdentifier(),
                            CACHE_NAME);
        }
        return cacheEntry;
    }

    public void clearCacheEntry(OIDCSessionIdStoreKey key) {

        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key.getSessionIdentifier(), CACHE_NAME);
    }
}
