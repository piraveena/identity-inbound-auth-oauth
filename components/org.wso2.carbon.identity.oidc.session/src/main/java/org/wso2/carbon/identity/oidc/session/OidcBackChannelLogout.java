package org.wso2.carbon.identity.oidc.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.servlet.OIDCBackChannelLogoutServlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Map;

/**
 * Created by piraveena on 9/29/17.
 */
public class OidcBackChannelLogout {
    private static final Log log= LogFactory.getLog(OidcBackChannelLogout.class);

    public void sendBackChannelLogout(HttpServletRequest request, HttpServletResponse response) throws
            IdentityOAuth2Exception, InvalidOAuthClientException {

        DefaultLogoutTokenBuilder logoutTokenBuilder = new DefaultLogoutTokenBuilder();
        Map<String, String> logoutToken_list = logoutTokenBuilder.buildLogoutToken(request, response);

        for (Map.Entry<String, String> map : logoutToken_list.entrySet()) {
            String token = map.getKey();
            String bcurl = map.getValue();
            log.info("Token: " + token + " " + "Back_channelLogout url: " + bcurl);


            HttpClient client = new DefaultHttpClient();
            HttpPost httpPost = new HttpPost(map.getValue());
            BasicNameValuePair nvp1 = new BasicNameValuePair("logout_token", token);
            ArrayList<BasicNameValuePair> list = new ArrayList<>();
            list.add(nvp1);
            try {
                httpPost.setEntity(new UrlEncodedFormEntity(list));
                HttpResponse httpResponse = client.execute(httpPost);
                if(log.isDebugEnabled()){
                    log.debug("successfully sent logout token to" + bcurl);
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (ClientProtocolException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }


        }
    }

}
