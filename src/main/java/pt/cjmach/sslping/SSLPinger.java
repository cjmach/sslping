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
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
    private final static String USER_AGENT = "sslping";
    private final static String PROXY_HOST;
    private final static int PROXY_PORT;

    private final SSLContext context;
    
    static {
        String systemProxyHost = System.getProperty("https.proxyHost");
        if (systemProxyHost != null && !systemProxyHost.isEmpty()) {
            PROXY_HOST = systemProxyHost;
            PROXY_PORT = Integer.getInteger("https.proxyPort");
        } else {
            PROXY_HOST = null;
            PROXY_PORT = 0;
        }
    }

    public SSLPinger() throws NoSuchAlgorithmException {
        this(SSLContext.getDefault());
    }

    public SSLPinger(String algorithm) throws NoSuchAlgorithmException, KeyManagementException {
        this(SSLContext.getInstance(algorithm));
        context.init(null, null, null);
    }

    private SSLPinger(SSLContext context) {
        this.context = context;
    }
    
    private SSLSocket createSSLSocket(String host, int port) throws IOException {
        if (PROXY_HOST == null) {
            SSLSocketFactory factory = context.getSocketFactory();
            return (SSLSocket) factory.createSocket(host, port);
        }
        return createTunneledSSLSocket(host, port);
    }
    
    /**
     * 
     * @param host
     * @param port
     * @return
     * @throws IOException 
     * @see https://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/samples/sockets/client/SSLSocketClientWithTunneling.java
     */
    private SSLSocket createTunneledSSLSocket(String host, int port) throws IOException {
        Socket proxySocket = new Socket(PROXY_HOST, PROXY_PORT);
        String proxyMsg = String.format("CONNECT %s:%d HTTP/1.1\r\nUser-Agent: %s\r\n\r\n", 
                                            host, port, USER_AGENT);
        byte[] proxyMsgBytes = proxyMsg.getBytes(StandardCharsets.US_ASCII);

        // send connect
        OutputStream outStream = proxySocket.getOutputStream();
        outStream.write(proxyMsgBytes);
        outStream.flush();

        // get proxy response
        InputStream inStream = proxySocket.getInputStream();
        byte[] replyBytes = new byte[200];
        int replyLen = 0;
        int newlinesSeen = 0;
        boolean headerDone = false;

        while (newlinesSeen < 2) {
            int i = inStream.read();
            if (i < 0) {
                throw new IOException("[ERROR] Unexpected EOF from proxy.");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone && replyLen < replyBytes.length) {
                    replyBytes[replyLen++] = (byte) i;
                }
            }
        }

        String response = new String(replyBytes, 0, replyLen, StandardCharsets.US_ASCII);
        if (!response.startsWith("HTTP/1.1 200")) {
            throw new IOException(String.format("[ERROR] Could not connect to proxy %s:%d. Status: %s",
                    PROXY_HOST, PROXY_PORT, response));
        }
        SSLSocketFactory factory = context.getSocketFactory();
        return (SSLSocket) factory.createSocket(proxySocket, host, port, true);
    }

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
