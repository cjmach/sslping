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
  -a, --algorithm=NAME   SSLContext algorithm to use. Default is determined by the JVM.
  -h, --help             Print help and exit.
  -H, --host=HOSTNAME    Try to establish secure communication with this host. Required option.
  -P, --port=NUMBER      Port to use. Default is 443.
  -v, --version          Print version and exit.
```

For example, the following command will check if it's possible to establish a 
secure connection with server server.example.com, listening on port 443:

```console
$ java -jar sslping.jar -H server.example.com
[INFO] Successfully connected.
```

If the connection has to go through a proxy server, you can use the following Java
system properties to setup the proxy hostname, port and optionally credentials:
- **https.proxyHost**: Hostname or IP address of the proxy server.
- **https.proxyPort**: Port of the proxy server to connect to.
- **https.proxyUser**: (Optional) Proxy user name.
- **https.proxyPassword**: (Optional) Proxy user password.

Example:

```console
$ java -Dhttps.proxyHost=proxy.example.com -Dhttps.proxyPort=3128 \
       -Dhttps.proxyUser=username -Dhttps.proxyPassword=passwd \
       -jar sslping.jar -H server.example.com
[INFO] Successfully connected
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