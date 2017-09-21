package org.wso2.carbon.identity.openidconnect;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

public interface ClaimAdder {

    /**
     *
     * @param request
     * @param tokenRespDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    Map<String, Object> getAdditionalClaims(OAuthAuthzReqMessageContext request, OAuth2AuthorizeRespDTO tokenRespDTO)
            throws IdentityOAuth2Exception;

    /**
     *
     * @param request
     * @param tokenRespDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    Map<String, Object> getAdditionalClaims(OAuthTokenReqMessageContext request, OAuth2AccessTokenRespDTO tokenRespDTO)
            throws IdentityOAuth2Exception;
}