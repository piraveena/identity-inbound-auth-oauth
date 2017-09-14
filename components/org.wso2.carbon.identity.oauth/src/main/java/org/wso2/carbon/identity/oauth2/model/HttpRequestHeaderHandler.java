package org.wso2.carbon.identity.oauth2.model;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;


public class HttpRequestHeaderHandler {
    private HttpRequestHeader[] httpRequestHeaders;
    private Cookie[] cookies;

    public HttpRequestHeaderHandler(HttpServletRequest request) {
        this.cookies = request.getCookies();
        Enumeration headerNames = request.getHeaderNames();
        if(headerNames != null) {
            ArrayList httpHeaderList;
            String headerName;
            ArrayList headerValueList;
            for(httpHeaderList = new ArrayList(); headerNames.hasMoreElements(); httpHeaderList.add(new HttpRequestHeader(headerName, (String[])headerValueList.toArray(new String[headerValueList.size()])))) {
                headerName = (String)headerNames.nextElement();
                Enumeration headerValues = request.getHeaders(headerName);
                headerValueList = new ArrayList();
                if(headerValues != null) {
                    while(headerValues.hasMoreElements()) {
                        headerValueList.add((String)headerValues.nextElement());
                    }
                }
            }

            this.httpRequestHeaders = (HttpRequestHeader[])httpHeaderList.toArray(new HttpRequestHeader[httpHeaderList.size()]);
        }

    }

    public HttpRequestHeader[] getHttpRequestHeaders() {
        return this.httpRequestHeaders;
    }

    public Cookie[] getCookies() {
        return this.cookies != null?this.cookies:null;
    }}
