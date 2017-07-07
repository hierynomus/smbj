package com.hierynomus.smbj.event;

public class ConnectionClosed implements SMBEvent {
    private String hostname;
    private int port;

    public ConnectionClosed(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }
}
