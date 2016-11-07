/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.protocol.commons.socket;

import javax.net.SocketFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public abstract class SocketClient {
    private static final int INITIAL_BUFFER_SIZE = 9000; // Size of a Jumbo frame.

    private final int defaultPort;

    private Socket socket;
    private InputStream input;
    private OutputStream output;

    private SocketFactory socketFactory = new ProxySocketFactory();

    private int soTimeout = 0;

    public SocketClient(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public void connect(String hostname, int port) throws IOException {
        connect(InetAddress.getByName(hostname), port);
    }

    public void connect(InetAddress host, int port) throws IOException {
        socket = socketFactory.createSocket(host, port);
        onConnect();
    }

    public void connect(InetAddress host, int port, InetAddress localAddr, int localPort) throws IOException {
        socket = socketFactory.createSocket(host, port, localAddr, localPort);
        onConnect();
    }

    public void connect(String hostname, int port, InetAddress localAddr, int localPort) throws IOException {
        connect(InetAddress.getByName(hostname), port, localAddr, localPort);
    }

    public void connect(InetAddress host) throws IOException {
        connect(host, defaultPort);
    }

    public void connect(String hostname) throws IOException {
        connect(hostname, defaultPort);
    }

    public void disconnect() throws IOException {
        if (socket != null) {
            socket.close();
            socket = null;
        }

        if (input != null) {
            input.close();
            input = null;
        }

        if (output != null) {
            output.close();
            output = null;
        }
    }

    public boolean isConnected() {
        return (socket != null) && socket.isConnected();
    }

    public void setSocketFactory(SocketFactory factory) {
        if (factory == null) {
            socketFactory = new ProxySocketFactory();
        } else {
            socketFactory = factory;
        }
    }

    public int getSoTimeout() {
        return soTimeout;
    }

    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    public Socket getSocket() {
        return socket;
    }

    protected InputStream getInputStream() {
        return input;
    }

    protected OutputStream getOutputStream() {
        return output;
    }

    protected void onConnect() throws IOException {
        socket.setSoTimeout(soTimeout);
        input = socket.getInputStream();
        output = new BufferedOutputStream(socket.getOutputStream(), INITIAL_BUFFER_SIZE);
    }

    public int getRemotePort() {
        return socket.getPort();
    }

    public InetAddress getRemoteAddress() {
        return socket.getInetAddress();
    }

    public String getRemoteHostname() {
        return getRemoteAddress().getHostName();
    }
}
