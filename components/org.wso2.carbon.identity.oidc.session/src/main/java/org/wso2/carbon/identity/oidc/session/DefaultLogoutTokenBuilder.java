package org.wso2.carbon.identity.oidc.session;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.map.HashedMap;
import org.json.JSONObject;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class DefaultLogoutTokenBuilder implements LogoutTokenBuilder {

    private OAuthServerConfiguration config = null;
    private JWSAlgorithm signatureAlgorithm = null;

    public DefaultLogoutTokenBuilder() throws IdentityOAuth2Exception {

        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());


    }

    @Override
    public Map<String,String> buildLogoutToken(HttpServletRequest request, HttpServletResponse response)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        Map<String,String> logout_tokenList=new HashMap<>();

       // send logout token to all RPs
        OIDCSessionState sessionState = getSessionState(request);


        for(String clientID :getSessionParticipants(sessionState)) {



            String sub = sessionState.getAuthenticatedUser();
            String jti = UUID.randomUUID().toString();

            String iss = "https://localhost:9443/carbon/";
            ArrayList<String> audience = new ArrayList<String>();
            audience.add(clientID);
            long lifetimeInMillis = Integer.parseInt(config.getOpenIDConnectBCLogoutTokenExpiration()) * 1000;
            long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
            Date iat = new Date(curTimeInMillis);
            String sid = getSidClaim(getSessionState(request));
            Map<String,Object> eventMap=new HashMap<>();
            eventMap.put("http://schemas.openid.net/event/backchannel-logout",new JSONObject());
            JSONObject event = new JSONObject(eventMap);

            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
            jwtClaimsSet.setSubject(sub);
            jwtClaimsSet.setIssuer(iss);
            jwtClaimsSet.setAudience(audience);
            jwtClaimsSet.setClaim("jti", jti);
            jwtClaimsSet.setClaim("event", event);
            jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
            jwtClaimsSet.setClaim("iat", iat);
            jwtClaimsSet.setClaim("sid", sid);

            boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
            String signingTenantDomain;
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientID);
           String backChannelLogoutUrl=oAuthAppDO.getBackChannelLogoutUrl();

            if(isJWTSignedWithSPKey) {

               //tenant domain of the SP
                signingTenantDomain=OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);

            }else {
                //tenant domain of the user
                signingTenantDomain=oAuthAppDO.getUser().getTenantDomain();
            }

            String logoutToken=OAuth2Util.signJWT(jwtClaimsSet,signatureAlgorithm,signingTenantDomain).serialize();
           // logout_tokenList.put(logoutToken,backChannelLogoutUrl);
            logout_tokenList.put(logoutToken,backChannelLogoutUrl);

        }
    return logout_tokenList;
    }


    /**
     * returns the session state of the obps cookie
     *
     * @param request
     * @return
     */
    public OIDCSessionState getSessionState(HttpServletRequest request) {

        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        String obpsCookieValue = opbsCookie.getValue();
        OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                .getOIDCSessionState(obpsCookieValue);
        return sessionState;
    }

    /**
     * return client id of all the RPs belong to same session
     *
     * @param sessionState
     * @return client id of all the RPs belong to same session
     */
    public Set<String> getSessionParticipants(OIDCSessionState sessionState) {

        Set<String> sessionParticipants = sessionState.getSessionParticipants();
        return sessionParticipants;
    }

    /**
     * returns the sid of the all the RPs belong to same session
     *
     * @param sessionState
     * @return
     */
    public String getSidClaim(OIDCSessionState sessionState) {

        String sidClaim = sessionState.getSidClaim();
        return sidClaim;
    }

}