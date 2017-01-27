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
package com.hierynomus.smbj;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.hierynomus.msdfsc.DFS;
import com.hierynomus.msdfsc.DFSException;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.tcp.DirectTcpTransport;

/**
 * Server Message Block Client API.
 */
public class SMBClient {
    /**
     * The default TCP port for SMB
     */
    public static final int DEFAULT_PORT = 445;

    private Map<String, Connection> connectionTable = new ConcurrentHashMap<>();

    private Config config;
    
    private DFS dfs;

    private SMBEventBus bus;

    public SMBClient() {
        this(new DefaultConfig());
    }

    public SMBClient(Config config) {
        this.config = config;
        bus = new SMBEventBus();
        dfs = new DFS();
    }

    /**
     * Connect to the host at <pre>hostname</pre> on the default port (445)
     *
     * @param hostname The hostname to connect to.
     * @return An established connection.
     * @throws IOException If the connection could not be established.
     */
    public Connection connect(String hostname) throws IOException {
        return getEstablishedOrConnect(hostname, DEFAULT_PORT);
    }

    /**
     * Connect to the host at <pre>hostname</pre> on the given port
     *
     * @param hostname The hostname to connect to.
     * @param port     The port to connect to
     * @return An established connection.
     * @throws IOException If the connection could not be established.
     */
    public Connection connect(String hostname, int port) throws IOException {
        return getEstablishedOrConnect(hostname, port);
    }

    private Connection getEstablishedOrConnect(String hostname, int port) throws IOException {
        String socketAddress = hostname + ":" + port;
        synchronized (this) {
            if (!connectionTable.containsKey(socketAddress)) {
                Connection connection = new Connection(config, this, new DirectTcpTransport(), bus);
                connection.connect(hostname, port);
                connectionTable.put(socketAddress, connection);
                return connection;
            }
            return connectionTable.get(hostname);
        }
    }

    public void resolvePathNotCoveredError(Session session, SMB2CreateRequest packet) throws DFSException {
        dfs.resolvePathNotCoveredError(session, packet);
    }

    public void resolveDFS(Session session, SmbPath smbPath) throws DFSException {
        dfs.resolveDFS(session, smbPath);
    }
    
    
}
