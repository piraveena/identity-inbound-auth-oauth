/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.listener;

import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertTrue;

public class IdentityOAuthEventHandlerTest extends IdentityBaseTest {

    IdentityOauthEventHandler identityOauthEventHandler;

    @Mock
    private MessageContext messageContext;

    @BeforeTest
    public void setUp() throws IllegalAccessException, InstantiationException {
        identityOauthEventHandler = new IdentityOauthEventHandler();
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(identityOauthEventHandler.getName(),
                "identityOauthEventHandler", "Valid getName().");
        assertNotEquals(identityOauthEventHandler.getName(),
                "identitykshfy", "Invalid getName().");
        assertFalse(Boolean.parseBoolean(identityOauthEventHandler.getName()),
                "Invalid getName().");
    }

    @Test
    public void testGetFriendlyName() throws Exception {
        assertEquals(identityOauthEventHandler.getFriendlyName(),
                "Identity Oauth Event Handler", "Valid getFriendlyName().");
        assertNotEquals(identityOauthEventHandler.getFriendlyName(),
                "identityOauthEventHandler", "Invalid getFriendlyName().");
    }

    @Test
    public void testGetPriority() throws Exception {

        assertEquals(identityOauthEventHandler.getPriority(messageContext), 51, "Valid priority.");
        assertNotEquals(identityOauthEventHandler.getPriority(messageContext), 100, "Invalid priority.");
    }

    @Test
    public void testRevokeTokensOfLockedUser() throws Exception {



        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        assertTrue(identityOathEventListener.doPostSetUserClaimValues(username, mockedMapClaims, profileName,
                userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostSetUserClaimValues(username, mockedMapClaims, profileName, userStoreManager));
    }

    @Test
    public void testDoPostSetUserClaimValue() throws Exception {
        IdentityEventListenerConfig listenerConfig = mock(IdentityEventListenerConfig.class);
        IdentityCacheConfig identityCacheConfig = mock(IdentityCacheConfig.class);
        ClaimCache claimCache = mock(ClaimCache.class);
        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(listenerConfig);
        when(StringUtils.isNotBlank(anyString())).thenReturn(true);

        assertTrue(identityOathEventListener.doPostSetUserClaimValue(username, userStoreManager));

        when(IdentityUtil.readEventListenerProperty(anyString(), anyString())).thenReturn(null);
        when(UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration())).thenReturn("DOMAIN_NAME");
        when(IdentityUtil.getIdentityCacheConfig(anyString(), anyString())).thenReturn(identityCacheConfig);
        when(claimCache.isEnabled()).thenReturn(false);

        IdentityOathEventListener listener = new IdentityOathEventListener();
        assertTrue(listener.doPostSetUserClaimValue(username, userStoreManager));
    }
}
