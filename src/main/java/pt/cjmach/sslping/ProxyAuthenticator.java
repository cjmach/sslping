/*
 *  Copyright 2024 Carlos Machado
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package pt.cjmach.sslping;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 *
 * @author cmachado
 */
public class ProxyAuthenticator extends Authenticator {
    private final String proxyHost;
    private final int proxyPort;
    private final String proxyUser;
    private final char[] proxyPassword;

    public ProxyAuthenticator(String proxyHost, int proxyPort, String proxyUser, char[] proxyPassword) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyUser = proxyUser;
        this.proxyPassword = proxyPassword;
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        String user = getProxyUser();
        if (user == null) {
            return null;
        }
        char[] passwd = getProxyPassword();
        String host = getRequestingHost();
        int port = getRequestingPort();
        if (host.equals(proxyHost) && port == proxyPort) {
            return new PasswordAuthentication(user, passwd);
        }
        return null;
    }
    
    protected String getProxyUser() {
        return proxyUser;
    }
    
    protected char[] getProxyPassword() {
        return proxyPassword;
    }
}
