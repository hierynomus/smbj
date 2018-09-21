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

import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.paths.DFSPathResolver;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.paths.SymlinkPathResolver;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.hierynomus.protocol.commons.IOUtils.closeSilently;

/**
 * Server Message Block Client API.
 */
public class SMBClient implements Closeable {
    /**
     * The default TCP port for SMB
     */
    public static final int DEFAULT_PORT = 445;

    private Map<String, Connection> connectionTable = new ConcurrentHashMap<>();

    private SmbConfig config;

    private SMBEventBus bus;
    private PathResolver pathResolver;

    public SMBClient() {
        this(SmbConfig.createDefaultConfig());
    }

    public SMBClient(SmbConfig config) {
        this(config, new SMBEventBus());
    }

    public SMBClient(SmbConfig config, SMBEventBus bus) {
        this.config = config;
        this.bus = bus;
        bus.subscribe(this);
        this.pathResolver = new SymlinkPathResolver(PathResolver.LOCAL);
        if (config.isDfsEnabled()) {
            this.pathResolver = new DFSPathResolver(this.pathResolver);
        }
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

    public PathResolver getPathResolver() {
        return pathResolver;
    }

    private Connection getEstablishedOrConnect(String hostname, int port) throws IOException {
        synchronized (this) {
            String hostPort = hostname + ":" + port;
            Connection cachedConnection = connectionTable.get(hostPort);
            if (cachedConnection == null || !cachedConnection.isConnected()) {
                Connection connection = new Connection(config, this, bus);
                try {
                    connection.connect(hostname, port);
                } catch (IOException e) {
                    closeSilently(connection); // Quietly close broken connection.
                    throw e;
                }
                connectionTable.put(hostPort, connection);
                return connection;
            }
            return connectionTable.get(hostPort);
        }
    }

    @Handler
    @SuppressWarnings("unused")
    private void connectionClosed(ConnectionClosed event) {
        synchronized (this) {
            String hostPort = event.getHostname() + ":" + event.getPort();
            connectionTable.remove(hostPort);
            logger.debug("Connection to << {} >> closed", hostPort);
        }
    }

    private static final Logger logger = LoggerFactory.getLogger(SMBClient.class);

    @Override
    public void close() {
        logger.info("Going to close all remaining connections");
        for (Connection connection : connectionTable.values()) {
            try {
                connection.close();
            } catch (Exception e) {
                logger.debug("Error closing connection to host {}", connection.getRemoteHostname());
                logger.debug("Exception was: ", e);
            }
        }
    }
}
