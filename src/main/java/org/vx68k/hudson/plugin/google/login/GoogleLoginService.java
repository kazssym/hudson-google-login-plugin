/*
 * GoogleLoginService
 * Copyright (C) 2014 Kaz Nishimura
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.vx68k.hudson.plugin.google.login;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Userinfoplus;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

/**
 * Federated login service for Google.
 *
 * @author Kaz Nishimura
 * @since 1.0
 */
@Extension
public class GoogleLoginService extends FederatedLoginService {

    private static final String URL_NAME = "google";

    protected static String getRedirectUri(String rootUrl) {
        return rootUrl + "federatedLoginService/" + URL_NAME + "/authorized";
    }

    /**
     * Handles a federated login request.
     *
     * @param request HTTP servlet request
     * @return HTTP response for the request
     */
    public HttpResponse doLogin(HttpServletRequest request) {
        Hudson application = Hudson.getInstance();
        GoogleLoginServiceProperty.Descriptor descriptor =
                application.getDescriptorByType(
                        GoogleLoginServiceProperty.Descriptor.class);

        GoogleAuthorizationCodeFlow flow =
                descriptor.getAuthorizationCodeFlow();
        GoogleAuthorizationCodeRequestUrl url =
                flow.newAuthorizationUrl();
        url.setRedirectUri(getRedirectUri(application.getRootUrl()));
        url.setState(request.getSession().getId());
        return HttpResponses.redirectTo(url.build());
    }

    /**
     * Handles an authorized redirection request.
     *
     * @param request HTTP servlet request
     * @param code authorization code
     * @param state state in the authorization request
     * @return HTTP response for the request
     */
    public HttpResponse doAuthorized(HttpServletRequest request,
            @QueryParameter(required = true) String code,
            @QueryParameter String state) {
        if (state != null) {
            if (!state.equals(request.getSession().getId())) {
                return HttpResponses.forbidden();
            }
        }

        Hudson application = Hudson.getInstance();
        GoogleLoginServiceProperty.Descriptor descriptor =
                application.getDescriptorByType(
                        GoogleLoginServiceProperty.Descriptor.class);

        GoogleAuthorizationCodeFlow flow =
                descriptor.getAuthorizationCodeFlow();
        GoogleAuthorizationCodeTokenRequest tokenRequest =
                flow.newTokenRequest(code);
        tokenRequest.setRedirectUri(getRedirectUri(application.getRootUrl()));

        Userinfoplus userinfoplus;
        try {
            GoogleTokenResponse tokenResponse = tokenRequest.execute();
            String accessToken = tokenResponse.getAccessToken();

            Oauth2 oauth2 = new Oauth2(flow.getTransport(), flow.getJsonFactory(),
                    flow.getRequestInitializer());
            Oauth2.Userinfo userinfo = oauth2.userinfo();

            Oauth2.Userinfo.Get userinfoGet = userinfo.get();
            userinfoGet.setOauthToken(accessToken);
            userinfoplus = userinfoGet.execute();
        } catch (IOException e) {
            return HttpResponses.error(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e);
        }

        if (!userinfoplus.isVerifiedEmail()) {
            return HttpResponses.forbidden();
        }

        Identity identity = new Identity(userinfoplus);
        if (User.current() != null) {
            try {
                identity.addToCurrentUser();
            } catch (IOException e) {
                return HttpResponses.error(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e);
            }
        } else {
            identity.signin();
        }

        return HttpResponses.redirectToContextRoot();
    }

    @Override
    public String getUrlName() {
        return URL_NAME;
    }

    @Override
    public Class<GoogleLoginServiceProperty> getUserPropertyClass() {
        return GoogleLoginServiceProperty.class;
    }

    protected class Identity extends FederatedIdentity {

        private final String identifier;
        private final String nickname;
        private final String fullName;
        private final String emailAddress;

        public Identity(Userinfoplus userinfoplus) {
            this.identifier = userinfoplus.getEmail();
            this.nickname = userinfoplus.getEmail();
            this.fullName = userinfoplus.getName();
            this.emailAddress = userinfoplus.getEmail();
        }

        @Override
        public String getIdentifier() {
            return identifier;
        }

        @Override
        public String getNickname() {
            return nickname;
        }

        @Override
        public String getFullName() {
            return fullName;
        }

        @Override
        public String getEmailAddress() {
            return emailAddress;
        }

        @Override
        public String getPronoun() {
            return "Google account";
        }
    }
}
