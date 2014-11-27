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

import java.util.List;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProvider;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

public abstract class UserResolver {

    private static final Log log = LogFactory.getLog(UserResolver.class);

    private OpenIDConnectProvider provider;

    public UserResolver(OpenIDConnectProvider provider) {
        this.provider = provider;
    }

    public OpenIDConnectProvider getProvider() {
        return provider;
    }

    public abstract String findNuxeoUser(OpenIDUserInfo userInfo);

    public DocumentModel createNuxeoUser(String nuxeoLogin) {
        DocumentModel userDoc;

        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);

            userDoc = userManager.getBareUserModel();
            userDoc.setPropertyValue(userManager.getUserIdField(), nuxeoLogin);

            userManager.createUser(userDoc);

        } catch (ClientException e) {
            log.error("Error while creating user " + nuxeoLogin + "in UserManager", e);
            return null;
        }

        return userDoc;
    }

    public abstract DocumentModel updateUserInfo(DocumentModel user, OpenIDUserInfo userInfo);

    public String findOrCreateNuxeoUser(OpenIDUserInfo userInfo) {
        DocumentModel userDoc=findNuxeoUser(userInfo);
        String user =userDoc.getId();
        if (user == null) {
            if (userInfo.getEmail() != null)
                user = userInfo.getEmail();
            else
                user = generateRandomUserId();
            userDoc = createNuxeoUser(user);
        }
        return user;
    }

    protected String generateRandomUserId() {
        String userId = null;

        try {
            UserManager userManager = Framework.getLocalService(UserManager.class);
            List<String> userIds = userManager.getUserIds();

            while (userId == null || userIds.contains(userId)) {
                userId = "user_" + RandomStringUtils.randomNumeric(4);
            }
        } catch (ClientException e) {
            log.error("Error while generating random user id", e);
            return null;
        }
        return userId;
    }
}