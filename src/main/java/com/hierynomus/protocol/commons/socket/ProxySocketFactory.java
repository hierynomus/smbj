package com.hierynomus.protocol.socket;

import javax.net.SocketFactory;
import java.io.IOException;
import java.net.*;

public class ProxySocketFactory extends SocketFactory {
    public static final int DEFAULT_CONNECT_TIMEOUT = 0;

    private Proxy proxy;
    private int connectTimeout;

    public ProxySocketFactory() {
        this(Proxy.NO_PROXY, DEFAULT_CONNECT_TIMEOUT);
    }

    public ProxySocketFactory(String proxyAddress, int proxyPort) {
        this(getHttpProxy(proxyAddress, proxyPort), DEFAULT_CONNECT_TIMEOUT);
    }

    public ProxySocketFactory(Proxy proxy) {
        this(proxy, DEFAULT_CONNECT_TIMEOUT);
    }

    public ProxySocketFactory(int connectTimeout) {
        this(Proxy.NO_PROXY, connectTimeout);
    }

    public ProxySocketFactory(Proxy proxy, int connectTimeout) {
        this.proxy = proxy;
        this.connectTimeout = connectTimeout;
    }

    @Override
    public Socket createSocket(String address, int port) throws IOException, UnknownHostException {
        return createSocket(new InetSocketAddress(address, port), null);
    }

    @Override
    public Socket createSocket(String address, int port, InetAddress localAddress, int localPort) throws IOException, UnknownHostException {
        return createSocket(new InetSocketAddress(address, port), new InetSocketAddress(localAddress, localPort));
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return createSocket(new InetSocketAddress(address, port), null);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocket(new InetSocketAddress(address, port), new InetSocketAddress(localAddress, localPort));
    }

    private Socket createSocket(InetSocketAddress address, InetSocketAddress bindAddress) throws IOException {
        Socket socket = new Socket(proxy);
        if (bindAddress != null) {
            socket.bind(bindAddress);
        }
        socket.connect(address, connectTimeout);
        return socket;
    }

    private static Proxy getHttpProxy(String proxyAddress, int proxyPort) {
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddress, proxyPort));
    }
}
