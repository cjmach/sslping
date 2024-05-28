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
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import picocli.CommandLine;
import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;

/**
 *
 * @author cmachado
 */
@Command(name = "sslping", // NOI18N
        description = "Checks if secure communication between your local JVM and a remote host is successful.") // NOI18N
public class Launcher implements Callable<Integer> {
    
    @Option(names = {"-H", "--host"}, paramLabel = "HOSTNAME", required = true, // NOI18N
            description = "Try to establish secure communication with this host. Required option.")
    private String host;
    
    @Option(names = {"-P", "--port"}, paramLabel = "NUMBER", defaultValue = "443",
            description = "Port to use. Default is ${DEFAULT-VALUE}.")
    private int port;
    
    @Option(names = {"-a", "--algorithm"}, paramLabel = "NAME", required = false,
            description = "SSLContext algorithm to use. Default is determined by the JVM.")
    private String algorithm;
    
    /**
     * 
     */
    @Option(names = {"-v", "--version"}, versionHelp = true, description = "Print version and exit.")
    @SuppressWarnings("FieldMayBeFinal")
    private boolean versionRequested = false;
    
    /**
     * 
     */
    @Option(names = {"-h", "--help"}, usageHelp = true, description = "Print help and exit.")
    @SuppressWarnings("FieldMayBeFinal")
    private boolean helpRequested = false;
    
    /**
     * 
     * @return
     * @throws Exception 
     */
    @Override
    public Integer call() throws Exception {
        SSLPinger pinger = null;
        try {
            pinger = algorithm == null ? new SSLPinger() : new SSLPinger(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("[ERROR] Unknown algorithm: " + algorithm);
            System.err.println("List of available algorithms:");
            List<String> algorithms = SSLPinger.getAvailableAlgorithms();
            for (String algo : algorithms) {
                System.err.println(algo);
            }
            return 1;
        }
        try {
            pinger.ping(host, port);
            System.out.println("[INFO] Successfully connected.");
            return 0;
        } catch (IOException ex) {
            System.out.println("[ERROR] I/O exception occurred: " + ex.getMessage());
            return 1;
        }
    }
    
    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        CommandLine cmdLine = new CommandLine(new Launcher());
        cmdLine.setCaseInsensitiveEnumValuesAllowed(true);
        int exitCode = cmdLine.execute(args);
        if (cmdLine.isVersionHelpRequested()) {
            String version = getVersion();
            System.out.println("sslping " + version); // NOI18N
        }
        System.exit(exitCode);
    }

    /**
     * 
     * @return 
     */
    private static String getVersion() {
        try {
            Manifest manifest = new Manifest(Launcher.class.getResourceAsStream("/META-INF/MANIFEST.MF")); // NOI18N
            Attributes attributes = manifest.getMainAttributes();
            String version = attributes.getValue("Implementation-Version"); // NOI18N
            return version;
        } catch (IOException ex) {
            System.err.println("Could not read MANIFEST.MF file: " + ex);
            return "";
        }
    }
}
