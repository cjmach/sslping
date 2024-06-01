# sslping
A simple command-line utility written in Java that checks if secure communication 
between your local JVM and a remote host is successful. It verifies that your 
certificates are valid and are properly installed on your local java keystore. 

# Requirements

- Java Runtime Environment 11

# Usage

```console
Usage: sslping [-hv] [-a=NAME] -H=HOSTNAME [-P=NUMBER]
Checks if secure communication between your local JVM and a remote host is successful.
  -a, --algorithm=NAME      SSLContext algorithm to use. Default is determined by the JVM.
  -h, --help                Print help and exit.
  -H, --host=HOSTNAME       Try to establish secure communication with this host. Required option.
  -p, --proxy-url=URL       (Optional) URL to the proxy server (e.g. http://192.168.1.2:3128).
  -P, --port=NUMBER         Port to use. Default is 443.
      --proxy-password=PWD  (Optional) Proxy user password.
      --proxy-user=USER     (Optional) Proxy user name.
  -v, --version             Print version and exit.
```

For example, the following command will check if it's possible to establish a 
secure connection with server server.example.com, listening on port 443:

```console
$ java -jar sslping.jar -H server.example.com
[INFO] Peer Handshake Info: CN=server.example.com
[INFO] Cipher suite: TLS_AES_256_GCM_SHA384

[INFO] Successfully connected.
```

If the connection has to go through a proxy server, you can use the following 
parameters to setup the proxy hostname, port and optionally credentials:

```console
$ java -jar sslping.jar -H server.example.com -p https://192.168.1.2:3128 \
       --proxy-user user --proxy-password passwd
[INFO] Connecting to host server.example.com:443 through secure proxy 192.168.1.2:3128...
[INFO] Proxy Handshake Info: CN=proxy-ca, C=AD
[INFO] Cipher suite: TLS_AES_256_GCM_SHA384

[INFO] Peer Handshake Info: CN=server.example.com
[INFO] Cipher suite: TLS_AES_256_GCM_SHA384

[INFO] Successfully connected.
```

# Testing

To test sslping, we used OPNSense + Squid running on a VM with a couple of network
interface cards (NIC):
- A host-only NIC for the LAN
- A NAT NIC for the WAN

Steps to configure Squid using OPNSense Web Interface:
1. Go to "System / Firmware / Plugins" and install **os-squid** plugin;
2. Go to "Services / Squid Web Proxy / Administration" and check "Enable proxy" 
on the "General Proxy Settings" tab;
3. On the "Forward Proxy" tab, ensure you have the following settings:
  - Proxy interfaces: LAN
  - Proxy port: 3128
  - Enable transparent HTTP proxy: checked
  - Enable SSL inspection: checked
  - SSL Proxy port: 3129
  - CA to use: Set or create one using the "CA Manager"
4. Click on the arrow next to the "Forward Proxy" tab and select "Access Control List". 
Ensure you have the following settings:
  - Allowed destination TCP port: 80 443
  - Allowed SSL ports: 443
5. To test proxy authentication, click on the arrow next to the "Forward Proxy" tab 
and select "Authentication Settings". Then, set the authentication method.
6. To test direct SSL connection to the proxy, add the following line to 
/usr/local/etc/squid/squid.conf file (replace "[LAN_IP]" with the LAN IP address):
```
https_port [LAN_IP]:3129 cert=/var/squid/ssl/ca.pem dynamic_cert_mem_cache_size=10MB generate-host-certificates=on
```
7. To test alternative authentication methods, such as "Digest" for example, add 
the following lines to squid.conf file. You must also create the "digest_passwd" file
with the user's credentials, following the .htdigest format (use `htdigest` tool or 
[htdigest Generator Tool Online](https://websistent.com/tools/htdigest-generator-tool/)):
```
auth_param digest program /usr/local/libexec/squid/digest_file_auth -c /usr/local/etc/squid/digest_passwd
auth_param digest realm Squid proxy-caching web server
```

# Building

To build this project you need:

- Java Development Kit 11
- Apache Maven 3.6.x or above

Assuming all the tools can be found on the PATH, simply go to the project 
directory and run the following command:

```console
$ mvn -B package
```

# Releasing

Go to the project directory and run the following commands:

```console
$ mvn -B release:prepare
$ mvn -B release:perform -Darguments='-Dmaven.deploy.skip=true' 
```

It will automatically assume the defaults for each required parameter, namely,
`releaseVersion` and `developmentVersion`. If it's necessary to control the values 
of each version, the `release:prepare` command can be run as follows:

```console
$ mvn -B release:prepare -DreleaseVersion={a release version} -DdevelopmentVersion={next version}-SNAPSHOT
```