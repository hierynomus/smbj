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
package com.hierynomus.smbj.transport.tcp.tunnel;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A Transport that translates the actual remote address to a connection on 'localhost' on the specified port.
 * <p>
 * This is useful for when using an SSH tunnel.
 *
 * @param <P>
 */
public class TunnelTransport<P extends Packet<?>> implements TransportLayer<P> {
    private TransportLayer<P> tunnel;
    private String tunnelHost;
    private int tunnelPort;

    public TunnelTransport(TransportLayer<P> tunnel, String tunnelHost, int tunnelPort) {
        this.tunnel = tunnel;
        this.tunnelHost = tunnelHost;
        this.tunnelPort = tunnelPort;
    }

    @Override
    public void write(P packet) throws TransportException {
        tunnel.write(packet);
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        InetSocketAddress localAddress = new InetSocketAddress(tunnelHost, tunnelPort);
        tunnel.connect(localAddress);
    }

    @Override
    public void disconnect() throws IOException {
        tunnel.disconnect();
    }

    @Override
    public boolean isConnected() {
        return tunnel.isConnected();
    }
}
