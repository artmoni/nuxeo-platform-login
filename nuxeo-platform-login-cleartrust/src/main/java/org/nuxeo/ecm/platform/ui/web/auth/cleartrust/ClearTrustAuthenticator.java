/*
 * (C) Copyright 2006-2009 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Nuxeo - initial API and implementation
 *
 * $Id: ClearTrustAuthenticator.java 33212 2009-04-22 14:06:56Z madarche $
 */

package org.nuxeo.ecm.platform.ui.web.auth.cleartrust;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.NuxeoAuthenticationFilter;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPluginLogoutExtension;
import org.nuxeo.ecm.platform.ui.web.util.BaseURL;

/**
 * @author M.-A. Darche
 */
public class ClearTrustAuthenticator implements NuxeoAuthenticationPlugin,
        NuxeoAuthenticationPluginLogoutExtension {

    // protected final static String CLEARTRUST_HEADER_UID =
    // "HTTP_CT_REMOTE_USER";
    protected final static String CLEARTRUST_HEADER_UID = "REMOTE_USER";

    protected final static String CLEARTRUST_COOKIE_SESSION_A = "ACTSESSION";

    protected final static String CLEARTRUST_COOKIE_SESSION = "CTSESSION";

    protected final static String NUXEO_CLEARTRUST_USER_NAME = "NUXEO_CLEARTRUST_USER_NAME";

    protected String cookieDomain = "";

    protected String cleartrustLoginUrl = "";

    protected String cleartrustLogoutUrl = "";

    private static final Log log = LogFactory.getLog(ClearTrustAuthenticator.class);

    public List<String> getUnAuthenticatedURLPrefix() {
        // There isn't any URL that should not need authentication
        return null;
    }

    /**
     * Redirects to the ClearTrust login page if the request doesn't contain
     * cookies indicating that a positive authentication occurred.
     * 
     * @return true if AuthFilter must stop execution (ie: login prompt
     *         generated a redirect), false otherwise
     */
    public Boolean handleLoginPrompt(HttpServletRequest request,
            HttpServletResponse response, String baseURL) {
        log.debug("handleLoginPrompt ...");
        log.debug("handleLoginPrompt requestURL = " + request.getRequestURL());
        Cookie[] cookies = request.getCookies();
        List<Cookie> cookieList = new ArrayList<Cookie>();
        for (Cookie cookie : cookies) {
            cookieList.add(cookie);
        }
        displayRequestInformation(request);
        displayCookieInformation(cookieList);
        String ctSession = getCookieValue(CLEARTRUST_COOKIE_SESSION, cookies);
        String ctSessionA = getCookieValue(CLEARTRUST_COOKIE_SESSION_A, cookies);
        log.debug("ctSession = " + ctSession);
        log.debug("ctSessionA = " + ctSessionA);

        boolean redirectToClearTrustLoginPage = false;
        if (ctSession == null) {
            log.debug("No ClearTrust session: not authorizing + redirecting to ClearTrust");
            redirectToClearTrustLoginPage = true;
        }

        if ("%20".equals(ctSessionA)) {
            log.debug("User has logout from ClearTrust: not authorizing + redirecting to ClearTrust");
            redirectToClearTrustLoginPage = true;
        }

        // The username, sent in the CT_REMOTE_USER header, is only sent by
        // ClearTrust in the first request. This happens only once and thus
        // should not be missed, and the username should be stored in a local
        // variable, here a cookie
        String ctUid = request.getHeader(CLEARTRUST_HEADER_UID);
        log.debug("ctUid = " + ctUid);
        if (ctUid != null) {
            log.debug("Saving ctUid " + ctUid + " for the whole session");
            request.getSession().setAttribute(NUXEO_CLEARTRUST_USER_NAME, ctUid);
        }

        if (redirectToClearTrustLoginPage) {
            String loginUrl = cleartrustLoginUrl;
            try {
                if (cleartrustLoginUrl == null || "".equals(cleartrustLoginUrl)) {
                    // loginUrl = baseURL
                    // + NuxeoAuthenticationFilter.DEFAULT_START_PAGE;
                    loginUrl = baseURL + "login.jsp";
                }

                // This is to avoid infinite redirections
                // String completeURI = request.getRequestURI();
                // log.debug("completeURI = " + completeURI);
                // String context = request.getContextPath() + '/';
                // log.debug("context = " + context);
                // String requestPage = completeURI.substring(context.length());
                // log.debug("requestPage = " + requestPage);
                log.debug("requestURL = " + request.getRequestURL());
                Object redirectUrlAttr = request.getSession().getAttribute(
                        "CLEARTRUST_AUTHENTICATOR_REDIRECT_TO_URL");
                if (redirectUrlAttr != null) {
                    String redirectUrl = (String) redirectUrlAttr;
                    log.debug("redirectUrl = " + redirectUrl);
                    if (redirectUrl.trim().equals(
                            request.getRequestURL().toString().trim())) {
                        log.debug("Stopping infinite redirect to URL : "
                                + redirectUrl);
                        return false;
                    } else {
                        log.debug("We will do a redirect");
                    }
                }

                log.debug("Redirecting to loginUrl: " + loginUrl);
                request.getSession().setAttribute(
                        "CLEARTRUST_AUTHENTICATOR_REDIRECT_TO_URL",
                        request.getRequestURL().toString());
                response.sendRedirect(loginUrl);
                return true;
            } catch (IOException ex) {
                log.error("Unable to redirect to ClearTrust login screen to "
                        + loginUrl, ex);
                return false;
            }
        }
        log.debug("ClearTrust authentication is OK, letting the user in.");
        return false;
    }

    public UserIdentificationInfo handleRetrieveIdentity(
            HttpServletRequest request, HttpServletResponse httpResponse) {
        log.debug("handleRetrieveIdentity ...");
        displayRequestInformation(request);
        Cookie[] cookies = request.getCookies();
        List<Cookie> cookieList = new ArrayList<Cookie>();
        for (Cookie cookie : cookies) {
            cookieList.add(cookie);
        }
        displayCookieInformation(cookieList);
        Object userNameAttr = request.getSession().getAttribute(
                NUXEO_CLEARTRUST_USER_NAME);
        if (userNameAttr == null) {
            log.debug("handleRetrieveIdentity No user known");
            return null;
        }
        String userName = (String) userNameAttr;
        UserIdentificationInfo uui = new UserIdentificationInfo(userName,
                "No password needed for ClearTrust authentication");
        log.debug("handleRetrieveIdentity going on with authenticated user = "
                + userName);
        return uui;
    }

    public Boolean needLoginPrompt(HttpServletRequest request) {
        // Returning true means that the handleLoginPrompt method will be called
        return true;
    }

    /**
     * @return true if there is a redirection
     */
    public Boolean handleLogout(HttpServletRequest request,
            HttpServletResponse response) {
        log.debug("handleLogout ...");
        expireCookie(CLEARTRUST_COOKIE_SESSION, request, response);
        expireCookie(CLEARTRUST_COOKIE_SESSION_A, request, response);
        log.debug("handleLogout DONE!");

        String baseURL = BaseURL.getBaseURL(request);
        // String logoutUrl = baseURL
        // + NuxeoAuthenticationFilter.DEFAULT_START_PAGE;
        String logoutUrl = baseURL;
        if (cleartrustLogoutUrl == null || "".equals(cleartrustLogoutUrl)) {
            logoutUrl = cleartrustLogoutUrl;
        }

        try {
            response.sendRedirect(logoutUrl);
            return true;
        } catch (IOException e) {
            log.error("Unable to redirect to the logout URL " + logoutUrl
                    + " :", e);
            return false;
        }
    }

    private String getCookieValue(String cookieName, Cookie[] cookies) {
        String cookieValue = null;
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                cookieValue = cookie.getValue();
            }
        }
        return cookieValue;
    }

    private void expireCookie(String cookieName, HttpServletRequest request,
            HttpServletResponse response) {
        log.debug("expiring cookie " + cookieName + "  ...");
        Cookie cookie = new Cookie(cookieName, "");
        // A zero value causes the cookie to be deleted
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
        log.debug("expiring cookie DONE");
    }

    protected void displayCookieInformation(List<Cookie> cookies) {
        log.debug(">>>>>>>>>>>>> Here are the cookies: ");
        for (Cookie cookie : cookies) {
            log.debug("displayCookieInformation cookie name: "
                    + cookie.getName() + " path: " + cookie.getPath()
                    + " domain: " + cookie.getDomain() + " max age: "
                    + cookie.getMaxAge() + " value: " + cookie.getValue());
        }
    }

    protected void displayRequestInformation(HttpServletRequest request) {
        log.debug(">>>>>>>>>>>>> Here is the request: ");
        for (Enumeration headerNames = request.getHeaderNames(); headerNames.hasMoreElements();) {
            String headerName = (String) headerNames.nextElement();
            log.debug("header " + headerName + " : "
                    + request.getHeader(headerName));
        }
        for (Enumeration attributeNames = request.getAttributeNames(); attributeNames.hasMoreElements();) {
            String attributeName = (String) attributeNames.nextElement();
            log.debug("attribute " + attributeName + " : "
                    + request.getAttribute(attributeName));
        }
        for (Enumeration parameterNames = request.getParameterNames(); parameterNames.hasMoreElements();) {
            String parameterName = (String) parameterNames.nextElement();
            log.debug("parameter " + parameterName + " : "
                    + request.getParameter(parameterName));
        }
    }

    public void initPlugin(Map<String, String> parameters) {
        log.debug("initPlugin v20");
        if (parameters.containsKey(ClearTrustParameters.COOKIE_DOMAIN)) {
            cookieDomain = parameters.get(ClearTrustParameters.COOKIE_DOMAIN);
        }
        if (parameters.containsKey(ClearTrustParameters.CLEARTRUST_LOGIN_URL)) {
            cleartrustLoginUrl = parameters.get(ClearTrustParameters.CLEARTRUST_LOGIN_URL);
        }
        if (parameters.containsKey(ClearTrustParameters.CLEARTRUST_LOGOUT_URL)) {
            cleartrustLogoutUrl = parameters.get(ClearTrustParameters.CLEARTRUST_LOGOUT_URL);
        }
    }

}
