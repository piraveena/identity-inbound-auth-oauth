package org.wso2.carbon.identity.oidc.session.servlet;


import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.DefaultLogoutTokenBuilder;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * Created by piraveena on 9/4/17.
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import com.hazelcast.web.SessionState;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * Created by piraveena on 9/1/17.
 */
public class OIDCBackChannelLogoutServlet extends HttpServlet {
    private static final Log log= LogFactory.getLog(OIDCBackChannelLogoutServlet.class);

    public void init() throws ServletException {
        log.info("OIDC Backchannel logout servlet has been started");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        log.info("OIDCBackChannelLogoutServlet: accessing get method ");
        log.info(request.toString());
        PrintWriter print=response.getWriter();
        try {
            DefaultLogoutTokenBuilder logoutTokenBuilder=new DefaultLogoutTokenBuilder();
           JWTClaimsSet logoutToken=logoutTokenBuilder.buildLogoutToken(request,response);

        } catch (IdentityOAuth2Exception e) {
           log.info("IdentityOAuthException");
        } catch (InvalidOAuthClientException e) {
            log.info("InvalidOAuthClientException");
        }

    }

    /**
     * returns the session state of the obps cookie
     *
     * @param sessionId
     * @return sessionState of the obps cookie
     */

    public OIDCSessionState getSessionState(String sessionId) {

        OIDCSessionState sessionState = OIDCSessionManagementUtil.getSessionManager()
                .getOIDCSessionState(sessionId);
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
     * @return sid of the all the RPs belong to same session
     */
    public String getSidClaim(OIDCSessionState sessionState) {

        String sidClaim = sessionState.getSidClaim();
        return sidClaim;
    }

    public void buildLogoutToken(OIDCSessionState sessionState){
        for(String clientId: getSessionParticipants(sessionState)) {
            String sub = sessionState.getAuthenticatedUser();
            String aud=clientId;
            String value= UUID.randomUUID().toString();
            JSONObject event=new JSONObject();
            event.put( "http://schemas.openid.net/event/backchannel-logout", new JSONObject());
            String iss = "https://localhost:9443/carbon/";

//            long lifetimeInMillis = Integer.parseInt(config.getOpenIDConnectIDTokenExpiration()) * 1000;
            long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
            Date iat=new Date(curTimeInMillis);


        }

    }

    public Cookie removeSession(Cookie cookie, HttpServletResponse response){
        if (cookie.getName().equals(OIDCSessionConstants.OPBS_COOKIE_ID)) {
            cookie.setMaxAge(0);
            cookie.setSecure(true);
            cookie.setPath("/");
            response.addCookie(cookie);
            return cookie;
        }
        return null;
    }

}



