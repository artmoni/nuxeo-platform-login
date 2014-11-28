/*
 * (C) Copyright 2006-2014 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Nelson Silva <nelson.silva@inevo.pt> - initial API and implementation
 *     jcarsique
 *     Nuxeo
 */

package org.nuxeo.ecm.platform.oauth2.openid.auth;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProvider;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProviderRegistry;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.ecm.core.api.DocumentModel
;
/**
 * Authenticator using OpenID to retrieve user identity.
 *
 * @author Nelson Silva <nelson.silva@inevo.pt>
 *
 */
public class OpenIDConnectAuthenticator implements NuxeoAuthenticationPlugin {

    private static final Log log = LogFactory.getLog(OpenIDConnectAuthenticator.class);

    public static final String STATE_URL_PARAM_NAME = "state";

    public static final String STATE_SESSION_ATTRIBUTE = STATE_URL_PARAM_NAME;

    public static final String CODE_URL_PARAM_NAME = "code";

    public static final String ERROR_URL_PARAM_NAME = "error";

    public static final String PROVIDER_URL_PARAM_NAME = "provider";

    public static final String REFRESH_TOKEN_URL_PARAM_NAME = "refresh";

    public static final String ACCESS_TOKEN_URL_PARAM_NAME = "token";

    public static final String USERINFO_KEY = "OPENID_USERINFO";

    public static final String PROPERTY_OAUTH_CREATE_USER = "nuxeo.oauth.auth.create.user";

    public static final String PROPERTY_SKIP_OAUTH_TOKEN = "nuxeo.skip.oauth.token.state.check";

    /**
     * @since 6.0
     */
    public static final String ID_TOKEN_URL_PARAM_NAME = "id_token";

    protected void sendError(HttpServletRequest req, String msg) {
        req.setAttribute(LOGIN_ERROR, msg);
    }

    @Override
    public List<String> getUnAuthenticatedURLPrefix() {
        return new ArrayList<>();
    }

    @Override
    public UserIdentificationInfo handleRetrieveIdentity(
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        // Checking if there was an error such as the user denied access
        String error = httpRequest.getParameter(ERROR_URL_PARAM_NAME);
        if (StringUtils.isNotBlank(error)) {
            sendError(httpRequest, "There was an error: \"" + error + "\".");
            return null;
        }

        // Choose OpenID provider
        String serviceProviderName = httpRequest.getParameter(PROVIDER_URL_PARAM_NAME);
        if (StringUtils.isBlank(serviceProviderName)) {
            sendError(httpRequest, "Missing OpenID Connect Provider ID.");
            return null;
        }
        OpenIDConnectProviderRegistry registry = Framework.getLocalService(OpenIDConnectProviderRegistry.class);
        OpenIDConnectProvider provider = registry.getProvider(serviceProviderName);
        if (provider == null) {
            sendError(httpRequest, "No service provider called: \""
                    + serviceProviderName + "\".");
            return null;
        }
        log.debug("provider: " + provider.getName());

        // Check the state token
        if (!Framework.isBooleanPropertyTrue(PROPERTY_SKIP_OAUTH_TOKEN)
                && !provider.verifyStateToken(httpRequest)) {
            sendError(httpRequest, "Invalid state parameter.");
        }

        // merge
        OpenIDUserInfo info = null;
        String code = httpRequest.getParameter(CODE_URL_PARAM_NAME);
        String refresh = httpRequest.getParameter(REFRESH_TOKEN_URL_PARAM_NAME);
        String accessToken = httpRequest.getParameter(ACCESS_TOKEN_URL_PARAM_NAME);
        String idToken = httpRequest.getParameter(ID_TOKEN_URL_PARAM_NAME);

        /*
         * Get access token either from URL,
         * or get one in exchange of an authorization code,
         * or using a refresh token
         */
        if (StringUtils.isNotBlank(accessToken)) { // Using an access token
            // TODO NXP-12775 check accessToken validity?
        }
        if (StringUtils.isBlank(accessToken)) {
            if (StringUtils.isNotBlank(code)) {
                log.debug("Using an authorization code to get an access token");
                accessToken = provider.getAccessToken(httpRequest, code);
            } else if (StringUtils.isNotBlank(refresh)) {
                log.debug("Using a refresh token to get an access token");
                accessToken = provider.getNewAccessToken(httpRequest, refresh);
            }
        }

        if (StringUtils.isNotBlank(idToken)) { // Using an ID token
            log.debug("id token: " + idToken);
            info = provider.getUserInfoFromIdToken(idToken);
        }
        if (StringUtils.isNotBlank(accessToken)) { // Using an access token
            log.debug("access token: " + accessToken);
            // TODO NXP-12775 merge if (info != null)
            info = provider.getUserInfo(accessToken);
        }

        if (StringUtils.isBlank(accessToken) && StringUtils.isBlank(idToken)
                || info == null) {
            // No solution found to authenticate the user
            sendError(httpRequest, "Couldn't get OpenID user info!");
            return null;
        }

        // Store the user info as a key in the httpRequestuest so apps can
        // use it later in the chain
        httpRequest.setAttribute(USERINFO_KEY, info);

        UserResolver userResolver = provider.getUserResolver();

        String userId;
        if (Framework.isBooleanPropertyTrue(PROPERTY_OAUTH_CREATE_USER)) {
            userId = userResolver.findOrCreateNuxeoUser(info);
        } else {
            userId = userResolver.findNuxeoUser(info).getId();
        }
        if (userId == null) {
            sendError(httpRequest,
                    "No user found with email: \"" + info.getEmail() + "\".");
            return null;
        }

        UserIdentificationInfo userIdent = new UserIdentificationInfo(userId,
                userId);
        userIdent.setAuthPluginName("TRUSTED_LM");
        return userIdent;
    }

    @Override
    public Boolean handleLoginPrompt(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse, String baseURL) {
        return false;
    }

    @Override
    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return false;
    }

    @Override
    public void initPlugin(Map<String, String> parameters) {
    }
}
