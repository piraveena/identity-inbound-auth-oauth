package org.wso2.carbon.identity.oauth2.model;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by piraveena on 8/22/17.
 */
public class HTTPRequestHeaderHandler {
    private  HttpRequestHeader[] httpRequestHeaders;

    public HTTPRequestHeaderHandler(HttpServletRequest request){

        //set all http headers
        Enumeration headerNames = request.getHeaderNames();
        if (headerNames != null) {
            List<HttpRequestHeader> httpHeaderList = new ArrayList<>();
            while (headerNames.hasMoreElements()) {
                String headerName = (String) headerNames.nextElement();
                // since it is possible for some headers to have multiple values let's add them all.
                Enumeration headerValues = request.getHeaders(headerName);
                List<String> headerValueList = new ArrayList<>();
                if (headerValues != null) {
                    while (headerValues.hasMoreElements()) {
                        headerValueList.add((String) headerValues.nextElement());
                    }
                }
                httpHeaderList.add(
                        new HttpRequestHeader(headerName, headerValueList.toArray(new String[headerValueList.size()])));
            }
            httpRequestHeaders = httpHeaderList.toArray(new HttpRequestHeader[httpHeaderList.size()]);
        }
    }

    public HttpRequestHeader[] getHttpRequestHeaders(){
        return httpRequestHeaders;
    }

}
