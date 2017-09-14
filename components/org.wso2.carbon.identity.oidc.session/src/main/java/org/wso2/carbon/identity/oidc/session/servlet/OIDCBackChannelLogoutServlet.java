package org.wso2.carbon.identity.oidc.session.servlet;


import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.HttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
        try {
            DefaultLogoutTokenBuilder logoutTokenBuilder=new DefaultLogoutTokenBuilder();
           Map<String,String> logoutToken_list=logoutTokenBuilder.buildLogoutToken(request,response);

          for(Map.Entry<String,String> map: logoutToken_list.entrySet()){
              String token=map.getKey();
              String bcurl=map.getValue();
              log.info("Token: "+token+" "+"Back_channelLogout url: "+ bcurl);

            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
            OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opBrowserStateCookie.getValue());

            HttpClient client = new DefaultHttpClient();
            HttpPost httpPost = new HttpPost(map.getValue());
            BasicNameValuePair nvp1= new BasicNameValuePair("logout_token",token);
            ArrayList<BasicNameValuePair> list=new ArrayList<>();
            list.add(nvp1);
            httpPost.setEntity(new UrlEncodedFormEntity(list));
            HttpResponse httpResponse = client.execute(httpPost);
            log.info(httpPost);

          }


        } catch (IdentityOAuth2Exception e) {
           log.info("IdentityOAuthException");
        } catch (InvalidOAuthClientException e) {
            log.info("InvalidOAuthClientException");
        }

    }
//


    public Cookie removeSession(HttpServletRequest request, HttpServletResponse response) {

        Cookie cookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
        return cookie;
    }
}



