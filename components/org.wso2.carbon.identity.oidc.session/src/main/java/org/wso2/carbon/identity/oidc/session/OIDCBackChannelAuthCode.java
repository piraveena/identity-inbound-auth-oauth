package org.wso2.carbon.identity.oidc.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Created by piraveena on 9/20/17.
 */
public class OIDCBackChannelAuthCode {
    private static Map<String,String> codeSid=new HashMap<>();
    private String sid;
    private static Log log = LogFactory.getLog(OIDCBackChannelAuthCode.class);


    public static void setSidCode(String accessCode,String sid){
        codeSid.put(accessCode,sid);
    }

    public  String getSid(String code) {

        Set set = codeSid.entrySet();
        Iterator iterator = set.iterator();
        while(iterator.hasNext()) {
            Map.Entry mentry = (Map.Entry)iterator.next();
            log.info("key is: "+ mentry.getKey() + " & Value is: ");
            if (mentry.getKey().equals(code)){
                sid=(String)mentry.getValue();
                return sid;
            }
        }

        return null;
    }

}
