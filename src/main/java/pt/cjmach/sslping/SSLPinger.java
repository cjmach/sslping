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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
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
    private SSLSocket createSSLSocket(String host, int port, URL proxyUrl, String proxyUser, char[] proxyPassword) throws IOException {
        if (proxyUrl == null) {
            System.err.printf("[INFO] Connecting to host %s:%d...", host, port);
            System.err.println();
            SSLSocketFactory factory = context.getSocketFactory();
            return (SSLSocket) factory.createSocket(host, port);
        }
        String protocol = proxyUrl.getProtocol();
        boolean secureProxy;
        switch (protocol) {
            case "http":
                secureProxy = false;
                break;
            case "https":
                secureProxy = true;
                break;
            default:
                throw new IllegalArgumentException("Unsupported protocol: " + protocol);
        }
        String proxyHost = proxyUrl.getHost();
        int proxyPort = proxyUrl.getPort();
        if (proxyPort < 0) {
            proxyPort = proxyUrl.getDefaultPort();
        }
        if (secureProxy) {
            System.err.printf("[INFO] Connecting to host %s:%d through secure proxy %s:%d...", 
                    host, port, proxyHost, proxyPort);
            System.err.println();
            return createSSLTunneledSSLSocket(proxyHost, proxyPort, proxyUser, proxyPassword, host, port);
        }
        System.err.printf("[INFO] Connecting to host %s:%d through proxy %s:%d...", 
                host, port, proxyHost, proxyPort);
        System.err.println();
        return createTunneledSSLSocket(proxyHost, proxyPort, proxyUser, proxyPassword, host, port);
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
    private SSLSocket createTunneledSSLSocket(String proxyHost, int proxyPort, 
                                              String proxyUser, char[] proxyPassword, 
                                              String host, int port) throws IOException {        
        Authenticator currentAuthenticator = Authenticator.getDefault();
        String tunnelingDisabledSchemes = System.getProperty("jdk.http.auth.tunneling.disabledSchemes");
        ProxyAuthenticator proxyAuthenticator = new ProxyAuthenticator(proxyHost, proxyPort, proxyUser, proxyPassword);
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
    
    /**
     * 
     * @param host
     * @param port
     * @return
     * @throws IOException 
     * @see https://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/samples/sockets/client/SSLSocketClientWithTunneling.java
     */
    private SSLSocket createSSLTunneledSSLSocket(String proxyHost, int proxyPort, 
                                                 String proxyUser, char[] proxyPassword, 
                                                 String host, int port) throws IOException {
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket proxySocket = (SSLSocket) factory.createSocket(proxyHost, proxyPort);
        proxySocket.addHandshakeCompletedListener(e -> {
            printHandshakeInfo("Proxy Handshake Info", e);
        });
        proxySocket.startHandshake();
        
        String proxyRequest = String.format("CONNECT %s:%d HTTP/1.1\r\nUser-Agent: %s\r\n\r\n", 
                                            host, port, "sslping");
        // send connect
        OutputStream outStream = proxySocket.getOutputStream();
        BufferedWriter writeBuffer = new BufferedWriter(new OutputStreamWriter(outStream, StandardCharsets.US_ASCII));
        writeBuffer.write(proxyRequest);
        writeBuffer.flush();

        // get proxy response
        InputStream inStream = proxySocket.getInputStream();
        BufferedReader readBuffer = new BufferedReader(new InputStreamReader(inStream, StandardCharsets.US_ASCII));
        String proxyResponse = readBuffer.readLine();
        if (proxyResponse == null) {
            throw new IOException("[ERROR] Could not get response from proxy.");
        }
        if (proxyResponse.startsWith("HTTP/1.1 407")) { // proxy requires authentication
            if (proxyUser == null) {
                throw new IOException("Proxy requires authentication and no credentials provided.");
            }
            // get authentication method and content length.
            String authMethod = null;
            String contentLength = null;
            Pattern authPattern = Pattern.compile("^Proxy-Authenticate:\\s*(\\w+)\\s*.+$", Pattern.CASE_INSENSITIVE);
            Pattern lengthPattern = Pattern.compile("^Content-Length:\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
            while ((proxyResponse = readBuffer.readLine()) != null && !proxyResponse.isEmpty()) {
                Matcher authMatcher = authPattern.matcher(proxyResponse);
                if (authMatcher.matches()) {
                    authMethod = authMatcher.group(1);
                }
                Matcher lengthMatcher = lengthPattern.matcher(proxyResponse);
                if (lengthMatcher.matches()) {
                    contentLength = lengthMatcher.group(1);
                }
            }
            if (contentLength != null) {
                long length = Long.parseLong(contentLength);
                long skipped = readBuffer.skip(length); // skip message body
                assert skipped == length;
            }
            if ("Basic".equalsIgnoreCase(authMethod)) {
                // send connect with authentication
                byte[] basicAuth = getBasicAuthentication(proxyUser, proxyPassword);
                String base64BasicAuth = Base64.getEncoder().encodeToString(basicAuth);
                proxyRequest = String.format("CONNECT %s:%d HTTP/1.1\r\nProxy-Authorization: Basic %s\r\nUser-Agent: %s\r\n\r\n", 
                                        host, port, base64BasicAuth, "sslping");
                writeBuffer.write(proxyRequest);
                writeBuffer.flush();

                // get proxy response
                proxyResponse = readBuffer.readLine();
            } else {
                throw new UnsupportedOperationException("Authentication method is not supported: " + authMethod);
            }
        }
        if (proxyResponse == null || !proxyResponse.startsWith("HTTP/1.1 200")) {
            throw new IOException(String.format("[ERROR] Could not connect to proxy. Status: %s", proxyResponse));
        }
        return (SSLSocket) factory.createSocket(proxySocket, host, port, true);
    }
    
    private static byte[] getBasicAuthentication(String user, char[] password) {
        byte[] userBytes = user.getBytes(StandardCharsets.UTF_8);
        
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] pwdBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(pwdBytes);
        byte[] basicAuth = new byte[userBytes.length + pwdBytes.length + 1];
        System.arraycopy(userBytes, 0, basicAuth, 0, userBytes.length);
        basicAuth[userBytes.length] = ':';
        System.arraycopy(pwdBytes, 0, basicAuth, userBytes.length + 1, pwdBytes.length);
        return basicAuth;
    }
    
    /**
     * Tries to connect to the host using a secure socket connection.
     * 
     * @param host The host to connect to.
     * @param port The port on the host to connect to. Must be between 1 and 65535.
     * @param proxyUrl
     * @param proxyUser
     * @param proxyPassword
     * @throws IOException If the connection fails, either because the host refused 
     * the connection or because there are no valid certificates on the local java 
     * keystore to successfully complete the secure connection handshake.
     */
    public void ping(String host, int port, URL proxyUrl, String proxyUser, char[] proxyPassword) throws IOException {
        if (host == null) {
            throw new NullPointerException("[ERROR] host is null.");
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException("[ERROR] host is empty.");
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("[ERROR] Port must be between 1 and 65535. Current value: " + port);
        }
        try (SSLSocket socket = createSSLSocket(host, port, proxyUrl, proxyUser, proxyPassword)) {
            socket.addHandshakeCompletedListener(e -> {
                printHandshakeInfo("Peer Handshake Info", e);
            });
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
    
    private static void printHandshakeInfo(String title, HandshakeCompletedEvent e) {
        System.err.printf("[INFO] %s: ", title);
        try {
            Principal p = e.getPeerPrincipal();
            System.err.println(p);
            System.err.println("[INFO] Cipher suite: " + e.getCipherSuite());
            System.err.println();
        } catch (SSLPeerUnverifiedException ex) {
            System.err.println(ex.getMessage());
        }
    }
}
