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
package com.hierynomus.smbj.event;

import com.hierynomus.smbj.connection.Connection;

public class ConnectionClosed implements SMBEvent {
    private String hostname;
    private int port;
    private Connection connection;

    public ConnectionClosed(String hostname, int port) {
        this(hostname, port, null);
    }

    /**
     * Create an event identifying the connection that closed.
     *
     * @param hostname The hostname of the closed connection.
     * @param port The port of the closed connection.
     * @param connection The closed connection, or {@code null} if unknown.
     */
    public ConnectionClosed(String hostname, int port, Connection connection) {
        this.hostname = hostname;
        this.port = port;
        this.connection = connection;
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    /**
     * Get the connection that closed.
     *
     * @return The closed connection, or {@code null} if it was not supplied.
     */
    public Connection getConnection() {
        return connection;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ConnectionClosed that = (ConnectionClosed) o;

        if (port != that.port) return false;
        return hostname.equals(that.hostname);
    }

    @Override
    public int hashCode() {
        int result = hostname.hashCode();
        result = 31 * result + port;
        return result;
    }
}
