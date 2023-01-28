/* ownCloud Android Library is available under MIT license
 *   Copyright (C) 2015 ownCloud Inc.
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 *
 */
package com.owncloud.android.lib.common;

import android.os.Parcel;

import com.nextcloud.common.OkHttpCredentialsUtil;

import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;

import java.util.ArrayList;
import java.util.List;

public class OwnCloudBasicCredentials implements OwnCloudCredentials {

    private String username;
    private String authToken;
    private boolean mAuthenticationPreemptive;

    public OwnCloudBasicCredentials(String username, String password) {
        this.username = username != null ? username : "";
        authToken = password != null ? password : "";
        mAuthenticationPreemptive = true;
    }

    public OwnCloudBasicCredentials(String username, String password, boolean preemptiveMode) {
        this.username = username != null ? username : "";
        authToken = password != null ? password : "";
        mAuthenticationPreemptive = preemptiveMode;
    }

    @Override
    public void applyTo(OwnCloudClient client) {
        List<String> authPrefs = new ArrayList<>(1);
        authPrefs.add(AuthPolicy.BASIC);

        client.getParams().setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, authPrefs);
        client.getParams().setAuthenticationPreemptive(mAuthenticationPreemptive);
        client.getParams().setCredentialCharset(OwnCloudCredentialsFactory.CREDENTIAL_CHARSET);
        client.getState().setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, authToken));
    }

    @Override
    public boolean authTokenExpires() {
        return false;
    }

    @Override
    public String toOkHttpCredentials() {
        return OkHttpCredentialsUtil.basic(username, authToken);
    }



    /*
     * Autogenerated Parcelable interface
     */

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(username);
        dest.writeString(authToken);
        dest.writeByte(mAuthenticationPreemptive ? (byte) 1 : (byte) 0);
    }

    protected OwnCloudBasicCredentials(Parcel in) {
        username = in.readString();
        authToken = in.readString();
        mAuthenticationPreemptive = in.readByte() != 0;
    }

    public static final Creator<OwnCloudBasicCredentials> CREATOR = new Creator<OwnCloudBasicCredentials>() {
        @Override
        public OwnCloudBasicCredentials createFromParcel(Parcel source) {
            return new OwnCloudBasicCredentials(source);
        }

        @Override
        public OwnCloudBasicCredentials[] newArray(int size) {
            return new OwnCloudBasicCredentials[size];
        }
    };

    public String getUsername() {
        return this.username;
    }

    public String getAuthToken() {
        return this.authToken;
    }

    @SuppressWarnings("EqualsReplaceableByObjectsCall")  // minApi < 19
    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof OwnCloudBasicCredentials)) return false;
        final OwnCloudBasicCredentials other = (OwnCloudBasicCredentials) o;
        final Object this$username = this.getUsername();
        final Object other$username = other.getUsername();
        if (this$username == null ? other$username != null : !this$username.equals(other$username))
            return false;
        final Object this$authToken = this.getAuthToken();
        final Object other$authToken = other.getAuthToken();
        if (this$authToken == null ? other$authToken != null : !this$authToken.equals(other$authToken))
            return false;
        return this.mAuthenticationPreemptive == other.mAuthenticationPreemptive;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $username = this.getUsername();
        result = result * PRIME + ($username == null ? 43 : $username.hashCode());
        final Object $authToken = this.getAuthToken();
        result = result * PRIME + ($authToken == null ? 43 : $authToken.hashCode());
        result = result * PRIME + (this.mAuthenticationPreemptive ? 79 : 97);
        return result;
    }
}