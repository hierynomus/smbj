/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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

import com.hierynomus.protocol.commons.socket.SocketClient;
import com.hierynomus.smbj.transport.TransportLayer;

import java.io.IOException;

/**
 * Server Message Block Client API.
 */
public class SMBClient extends SocketClient implements AutoCloseable {
    public static final int DEFAULT_PORT = 445;
    private final TransportLayer transport;
    private Config config;

    public SMBClient() {
        this(new DefaultConfig());
    }

    public SMBClient(Config config) {
        super(DEFAULT_PORT);
        this.config = config;
        this.transport = new TransportLayer(config);
    }

    @Override
    public void close() throws Exception {
        disconnect();
    }

    /** On connection establishment, also initializes the transport via {@link TransportLayer#init}. */
    @Override
    protected void onConnect()
            throws IOException {
        super.onConnect();
        transport.init(getRemoteHostname(), getRemotePort(), getInputStream(), getOutputStream());
    }

}
