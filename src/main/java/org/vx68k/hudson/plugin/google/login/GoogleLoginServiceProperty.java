/*
 * GoogleLoginServiceProperty
 * Copyright (C) 2014-2015 Kaz Nishimura
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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserPropertyDescriptor;
import hudson.security.FederatedLoginServiceUserProperty;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.oauth2.Oauth2Scopes;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

/**
 * User property for Google accounts.
 *
 * @author Kaz Nishimura
 * @since 1.0
 */
public class GoogleLoginServiceProperty
        extends FederatedLoginServiceUserProperty {

    @DataBoundConstructor
    public GoogleLoginServiceProperty(Collection<String> identifiers) {
        super(identifiers);
    }

    @Extension
    public static final class Descriptor extends UserPropertyDescriptor {

        private String clientID = "";
        private String clientSecret = "";

        public Descriptor() {
            load();
        }

        public String getClientID() {
            return clientID;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientID(String clientID) {
            this.clientID = clientID;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public GoogleAuthorizationCodeFlow getAuthorizationCodeFlow() {
            Collection<String> scopes = Collections.singleton(
                    Oauth2Scopes.USERINFO_EMAIL);
            return new GoogleAuthorizationCodeFlow(new NetHttpTransport(),
                    JacksonFactory.getDefaultInstance(), getClientID(),
                    getClientSecret(), scopes);
        }

        @Override
        public GoogleLoginServiceProperty newInstance(User user) {
            return new GoogleLoginServiceProperty(new HashSet<String>());
        }

        @Override
        public boolean isEnabled() {
            return !getClientID().isEmpty() && !getClientSecret().isEmpty();
        }

        @Override
        public GoogleLoginServiceProperty newInstance(StaplerRequest request,
                JSONObject formData) throws FormException {
            Set<String> identifiers = new HashSet<String>();
            Object value = formData.get("identifiers");
            if (value instanceof JSONArray) {
                for (Object i : (JSONArray) value) {
                    JSONObject entry = (JSONObject) i;
                    identifiers.add(entry.getString(""));
                }
            } else {
                assert value instanceof JSONObject;
                JSONObject entry = (JSONObject) value;
                identifiers.add(entry.getString(""));
            }
            return new GoogleLoginServiceProperty(identifiers);
        }

        @Override
        public String getDisplayName() {
            return "Google Login";
        }

        @Override
        public boolean configure(StaplerRequest request, JSONObject json)
                throws FormException {
            boolean ready = super.configure(request, json);
            if (ready) {
                setClientID(json.getString("clientID"));
                setClientSecret(json.getString("clientSecret"));
                save();
            }
            return ready;
        }
    }
}
