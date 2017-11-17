/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oidc.session;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * This is the logout token generator for the OpenID Connect back-channel logout Implementation. This
 * Logout token Generator utilizes the Nimbus SDK to build the Logout token.
 */
public class DefaultLogoutTokenBuilder implements LogoutTokenBuilder {

    public static final Log log = LogFactory.getLog(DefaultLogoutTokenBuilder.class);
    private OAuthServerConfiguration config = null;
    private JWSAlgorithm signatureAlgorithm = null;
    private static final String OPENID_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";

    public DefaultLogoutTokenBuilder() throws IdentityOAuth2Exception {
        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(config.getIdTokenSignatureAlgorithm());
    }

    @Override
    public Map<String, String> buildLogoutToken(HttpServletRequest request)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {
        String clientIdInIDTokenHint = getClientIdFromIDTokenHint(request);
        Map<String, String> logoutTokenList = new HashMap<>();
        // Send logout token to all RPs.
        OIDCSessionState sessionState = getSessionState(request);
        if (sessionState != null) {
            Set<String> sessionParticipants = getSessionParticipants(sessionState);
            if (!sessionParticipants.isEmpty()) {
                for (String clientID : sessionParticipants) {
                    OAuthAppDO oAuthAppDO = getOAuthAppDO(clientID);
                    String backChannelLogoutUrl = oAuthAppDO.getBackChannelLogoutUrl();
                    if (clientID.equals(clientIdInIDTokenHint)){
                        // No need to send logut token if the client id of the RP initiated logout is known.
                        continue;
                    }
                    if (!backChannelLogoutUrl.isEmpty()) {
                        // Send back-channel logout request to all RPs those registered their back-channel logout uri.
                        String tenantDomain = getTenanatDomain(oAuthAppDO);

                        String sub = sessionState.getAuthenticatedUser();
                        String jti = UUID.randomUUID().toString();
                        String iss = getIssuer(tenantDomain);
                        List<String> audience = getAudience(clientID);
                        long logoutTokenValidityInMillis = getLogoutTokenExpiryInMillis();
                        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
                        Date iat = new Date(currentTimeInMillis);
                        String sid = getSidClaim(sessionState);
                        JSONObject event = new JSONObject().put("http://schemas.openidnet/event/backchannel-logout",
                                new JSONObject());

                        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
                        jwtClaimsSet.setSubject(sub);
                        jwtClaimsSet.setIssuer(iss);
                        jwtClaimsSet.setAudience(audience);
                        jwtClaimsSet.setClaim("jti", jti);
                        jwtClaimsSet.setClaim("event", event);
                        jwtClaimsSet.setExpirationTime(new Date(currentTimeInMillis + logoutTokenValidityInMillis));
                        jwtClaimsSet.setClaim("iat", iat);
                        jwtClaimsSet.setClaim("sid", sid);

                        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
                        String signingTenantDomain;

                        if (isJWTSignedWithSPKey) {
                            // Tenant domain of the SP.
                            signingTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                        } else {
                            // Tenant domain of the user.
                            signingTenantDomain = oAuthAppDO.getUser().getTenantDomain();
                        }
                        String logoutToken =
                                OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
                        logoutTokenList.put(logoutToken, backChannelLogoutUrl);
                    }
                }
            }
        }
        return logoutTokenList;
    }

    /**
     * Returns the OIDCsessionState of the obps cookie
     *
     * @param request
     * @return
     */
    private OIDCSessionState getSessionState(HttpServletRequest request) {
        Cookie opbsCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        String obpsCookieValue = opbsCookie.getValue();
        OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                .getOIDCSessionState(obpsCookieValue);
        return sessionState;
    }

    /**
     * Return client id of all the RPs belong to same session.
     *
     * @param sessionState
     * @return client id of all the RPs belong to same session
     */
    private Set<String> getSessionParticipants(OIDCSessionState sessionState) {
        Set<String> sessionParticipants = sessionState.getSessionParticipants();
        return sessionParticipants;
    }

    /**
     * Returns the sid of the all the RPs belong to same session.
     *
     * @param sessionState
     * @return
     */
    private String getSidClaim(OIDCSessionState sessionState) {
        String sidClaim = sessionState.getSidClaim();
        return sidClaim;
    }

    private IdentityProvider getResidentIdp(String tenantDomain) throws IdentityOAuth2Exception {
        try {
            return IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Returning issuer of the tenant domain.
     *
     * @param tenantDomain
     * @return issuer
     * @throws IdentityOAuth2Exception
     */
    private String getIssuer(String tenantDomain) throws IdentityOAuth2Exception {
        IdentityProvider identityProvider = getResidentIdp(tenantDomain);
        FederatedAuthenticatorConfig[] fedAuthnConfigs =
                identityProvider.getFederatedAuthenticatorConfigs();
        // Get OIDC authenticator.
        FederatedAuthenticatorConfig oidcAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        // Setting issuer.
        String issuer =
                IdentityApplicationManagementUtil.getProperty(oidcAuthenticatorConfig.getProperties(),
                        OPENID_IDP_ENTITY_ID).getValue();
        return issuer;
    }

    private OAuthAppDO getOAuthAppDO(String clientID) throws IdentityOAuth2Exception, InvalidOAuthClientException {
        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientID);
        return oAuthAppDO;
    }

    private String getTenanatDomain(OAuthAppDO oAuthAppDO) {
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        return tenantDomain;
    }

    private List<String> getAudience(String clientID) {
        ArrayList<String> audience = new ArrayList<String>();
        audience.add(clientID);
        return audience;
    }

    private long getLogoutTokenExpiryInMillis() {
        return Integer.parseInt(config.getOpenIDConnectBCLogoutTokenExpiration()) *
                1000L;
    }

    private String getClientIdFromIDTokenHint(HttpServletRequest request) {
        String clientId = null;
        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);
        if (StringUtils.isNotBlank(idTokenHint)) {
            try {
                clientId = extractClientFromIdToken(idTokenHint);
            } catch (ParseException e) {
                String msg = "No valid session found for the received session state.";
                log.error(msg, e);
            }
        }
        return clientId;
    }

    private String extractClientFromIdToken(String idToken) throws ParseException {
        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

}
