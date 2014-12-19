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
import java.security.GeneralSecurityException;
import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;

/**
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

    public HttpResponse doLogin() {
        Hudson application = Hudson.getInstance();
        GoogleLoginServiceProperty.Descriptor descriptor =
                application.getDescriptorByType(
                        GoogleLoginServiceProperty.Descriptor.class);

        GoogleAuthorizationCodeFlow flow =
                descriptor.getAuthorizationCodeFlow();
        GoogleAuthorizationCodeRequestUrl url =
                flow.newAuthorizationUrl();
        url.setRedirectUri(getRedirectUri(application.getRootUrl()));
        return HttpResponses.redirectTo(url.build());
    }

    public HttpResponse doAuthorized(
            @QueryParameter(required = true) String code) {
        Hudson application = Hudson.getInstance();
        GoogleLoginServiceProperty.Descriptor descriptor =
                application.getDescriptorByType(
                        GoogleLoginServiceProperty.Descriptor.class);

        GoogleAuthorizationCodeFlow flow =
                descriptor.getAuthorizationCodeFlow();
        GoogleAuthorizationCodeTokenRequest tokenRequest =
                flow.newTokenRequest(code);
        tokenRequest.setRedirectUri(getRedirectUri(application.getRootUrl()));

        GoogleIdToken.Payload tokenPayload;
        try {
            GoogleTokenResponse tokenResponse = tokenRequest.execute();

            GoogleIdToken token = tokenResponse.parseIdToken();
            try {
                GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier(
                        flow.getTransport(), flow.getJsonFactory());
                if (!verifier.verify(token)) {
                    return HttpResponses.error(500, "ID token is not valid");
                }
            } catch (GeneralSecurityException e) {
                return HttpResponses.error(500, e);
            }

            tokenPayload = token.getPayload();
        } catch (IOException e) {
            return HttpResponses.error(500, e);
        }

        String email = tokenPayload.getEmail();
        if (email == null) {
            return HttpResponses.error(403, "Email is unknown");
        }

        Identity identity = new Identity(email);
        if (User.current() != null) {
            try {
                identity.addToCurrentUser();
            } catch (IOException e) {
                return HttpResponses.error(500, e);
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

        private final String email;

        public Identity(String email) {
            this.email = email;
        }

        public String getEmail() {
            return email;
        }

        @Override
        public String getIdentifier() {
            return getEmail();
        }

        @Override
        public String getNickname() {
            return getEmail();
        }

        @Override
        public String getFullName() {
            return "(Not included)";
        }

        @Override
        public String getEmailAddress() {
            return getEmail();
        }

        @Override
        public String getPronoun() {
            return "Google account";
        }
    }
}
