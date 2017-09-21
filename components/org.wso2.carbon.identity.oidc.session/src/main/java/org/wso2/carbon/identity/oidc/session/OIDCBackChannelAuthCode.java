package org.wso2.carbon.identity.oidc.session;

/**
 * Created by piraveena on 9/20/17.
 */
public class OIDCBackChannelAuthCode {
    private String code;
    private String sid;

    public OIDCBackChannelAuthCode(String code){
        this.code=code;
    }
    public void setSid(String sid){this.sid= sid; }

    public  String getSid(){ return  sid; }

}
