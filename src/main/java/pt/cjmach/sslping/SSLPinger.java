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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author cmachado
 */
public class SSLPinger {
    private final SSLContext context;
    
    /**
     * Creates a new instance of {@link SSLPinger} that uses the default SSLContext
     * algorithm.
     * @throws NoSuchAlgorithmException 
     */
    public SSLPinger() throws NoSuchAlgorithmException {
        this(SSLContext.getDefault());
    }

    /**
     * Creates a new instance of {@link SSLPinger} with the SSLContext algorithm 
     * specified through the parameter.
     * @param algorithm The SSLContext algorithm to use.
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException 
     */
    public SSLPinger(String algorithm) throws NoSuchAlgorithmException, KeyManagementException {
        this(SSLContext.getInstance(algorithm));
        context.init(null, null, null);
    }

    /**
     * 
     * @param context 
     */
    private SSLPinger(SSLContext context) {
        this.context = context;
    }
    
    /**
     * 
     * @param host
     * @param port
     * @return
     * @throws IOException 
     */
    private SSLSocket createSSLSocket(String host, int port) throws IOException {
        String proxyHost = getProxyHost();
        Integer proxyPort = getProxyPort();
        if (proxyHost != null) {
            return createTunneledSSLSocket(proxyHost, proxyPort, host, port);
        }
        SSLSocketFactory factory = context.getSocketFactory();
        return (SSLSocket) factory.createSocket(host, port);
    }
    
    /**
     * Creates a {@link javax.net.ssl.SSLSocket} instance that communicates 
     * through a proxy server.
     * @param proxyHost The proxy host to connect to.
     * @param proxyPort The port on the proxy host to connect to.
     * @param host The host to connect to.
     * @param port The port on the host to connect to. Must be between 1 and 65535.
     * @return An instance of {@link javax.net.ssl.SSLSocket} setup to tunnel the 
     * communication through a proxy server.
     * @throws IOException 
     */
    private SSLSocket createTunneledSSLSocket(String proxyHost, int proxyPort, String host, int port) throws IOException {
        Authenticator currentAuthenticator = Authenticator.getDefault();
        String tunnelingDisabledSchemes = System.getProperty("jdk.http.auth.tunneling.disabledSchemes");
        ProxyAuthenticator proxyAuthenticator = new ProxyAuthenticator(proxyHost, proxyPort);
        try {
            
            Authenticator.setDefault(proxyAuthenticator);
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
            
            SocketAddress proxyAddr = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, proxyAddr);
            Socket proxySocket = new Socket(proxy);
            
            SocketAddress hostAddr = new InetSocketAddress(host, port);
            proxySocket.connect(hostAddr);
            
            SSLSocketFactory factory = context.getSocketFactory();
            return (SSLSocket) factory.createSocket(proxySocket, host, port, true);
        } finally {
            Authenticator.setDefault(currentAuthenticator);
            if (tunnelingDisabledSchemes != null) {
                System.setProperty("jdk.http.auth.tunneling.disabledSchemes", tunnelingDisabledSchemes);
            }
        }
    }
    
    private static String getProxyHost() {
        String proxyHost = System.getProperty("http.proxyHost");
        return proxyHost == null || proxyHost.isEmpty() ? null : proxyHost;
    }
    
    private static Integer getProxyPort() {
        return Integer.getInteger("http.proxyPort");
    }

    /**
     * Tries to connect to the host using a secure socket connection.
     * 
     * @param host The host to connect to.
     * @param port The port on the host to connect to. Must be between 1 and 65535.
     * @throws IOException If the connection fails, either because the host refused 
     * the connection or because there are no valid certificates on the local java 
     * keystore to successfully complete the secure connection handshake.
     */
    public void ping(String host, int port) throws IOException {
        if (host == null) {
            throw new NullPointerException("[ERROR] host is null.");
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException("[ERROR] host is empty.");
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("[ERROR] Port must be between 1 and 65535. Current value: " + port);
        }
        try (SSLSocket socket = createSSLSocket(host, port)) {
            socket.startHandshake();        
            ping(socket);
        }
    }
    
    /**
     * Sends one byte to the host connected through the socket.
     * 
     * @param socket The socket to use.
     * @throws IOException If the operation fails.
     */
    private void ping(SSLSocket socket) throws IOException {
        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();

        // Send a byte to the server
        output.write(1);

        while (input.available() > 0) {
            long skipped = input.skip(Long.MAX_VALUE);
            if (skipped != Long.MAX_VALUE) {
                break;
            }
        }
    }

    /**
     * Returns a list of algorithm names that can be used to create an instance 
     * of {@link javax.net.ssl.SSLContext}.
     * @return List of algorithm names.
     * @see https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#sslcontext-algorithms
     */
    public static List<String> getAvailableAlgorithms() {
        Provider[] providers = Security.getProviders();
        List<String> result = new ArrayList<>();
        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                result.add(service.getAlgorithm());
            }
        }
        return result;
    }
}
