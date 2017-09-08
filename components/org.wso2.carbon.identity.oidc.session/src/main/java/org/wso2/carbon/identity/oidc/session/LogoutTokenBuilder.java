package org.wso2.carbon.identity.oidc.session;

import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public interface LogoutTokenBuilder {

    /**
     *
     * @param request
     * @return
     * @throws IdentityOAuth2Exception
     */
    public JWTClaimsSet buildLogoutToken(HttpServletRequest request, HttpServletResponse response)
            throws IdentityOAuth2Exception, InvalidOAuthClientException;
}
