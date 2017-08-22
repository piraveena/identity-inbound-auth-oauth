package org.wso2.carbon.identity.oidc.session.servlet;

import jdk.nashorn.api.scripting.JSObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.poi.hwpf.usermodel.DateAndTime;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
//import org.joda.time.DateTime;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.zip.DataFormatException;

/**
 * Created by piraveena on 7/31/17.
 */
public class LogoutToken {
    //logout tokLocalAndOutboundAuthenticationConfig configen claims
    private  String iss = "https://localhost:9443/carbon/";
    private String sub="subject";
    private String aud="audience";
    private String iat;
    private long jti;
    private String sid;
    private JSONObject event;

    private static final Log log = LogFactory.getLog(LogoutToken.class);

    public void setSub(ServiceProvider service){   //setting subject- here username or anything
       // LocalAndOutboundAuthenticationConfig config=new LocalAndOutboundAuthenticationConfig();
       // service.getLocalAndOutBoundAuthenticationConfig().
       // LocalAndOutboundAuthenticationConfig.class.
       // log.info("user subject:"+ LocalAndOutboundAuthenticationConfig.getSubjectClaimUri());
    }
    public void setAud(String aud){ //setting audience. This should be the client_id of the RP
        this.aud=aud;
    }

    public void setJti(){                                                         //10 digit token ID for logout
        this.jti=(long)(Math.random()*100000000 + 1000000000L);
    }

    public void setEvent(){
        this.event=new JSONObject();
        event.put( "http://schemas.openid.net/event/backchannel-logout", new JSONObject());


    }


    public String getIss(){             //return issuer id- url of OP
        return this.iss;
    }
    public String getSub(){    //return subject
        return this.sub;
    }
    public String getAud(){  //return audiences
        return this.aud;
    }
    public long getIat(){         //return issuing time. Time should 1970-01-01 00:00:00

        Date current=new Date();
        return current.getTime();

    }

    public long getJti(){           //return id of the token
        return this.jti;
    }
    public JSONObject getEvent(){
        return this.event;
    }


}
