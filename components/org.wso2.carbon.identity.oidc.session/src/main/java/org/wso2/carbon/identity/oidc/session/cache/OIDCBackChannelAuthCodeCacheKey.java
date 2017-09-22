package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.oauth.cache.CacheKey;
import org.wso2.carbon.identity.oidc.session.OIDCBackChannelAuthCode;

/**
 * Created by piraveena on 9/21/17.
 */
public class OIDCBackChannelAuthCodeCacheKey extends CacheKey {
    private String authCode;

    public void setAuthCode(String authCode){
        this.authCode=authCode;
    }

    public String getAuthCode(){
        return authCode;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof OIDCBackChannelAuthCode)) {
            return false;
        }
        return this.authCode.equals(((OIDCBackChannelAuthCodeCacheKey) o).getAuthCode());

    }

    @Override
    public int hashCode() {

        return authCode.hashCode();
    }
}
