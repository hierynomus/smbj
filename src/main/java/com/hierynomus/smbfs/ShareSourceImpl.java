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
package com.hierynomus.smbfs;

import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

import java.io.IOException;

/**
 * Keeps a single {@link Session}/{@link DiskShare} alive across calls instead of
 * opening a new connection/session/tree-connect for every single filesystem
 * operation. If the underlying connection was dropped (a {@link TransportException}),
 * a single reconnect attempt is made transparently.
 */
class ShareSourceImpl implements ShareSource {

    private final SMBClient client;
    private final String host;
    private final int port;
    private final AuthenticationContext context;

    private volatile boolean closed = false;

    private Session session;
    private DiskShare share;

    ShareSourceImpl(SMBClient client, String host, int port, AuthenticationContext context) {
        this.client = client;
        this.host = host;
        this.port = port;
        this.context = context;
    }

    @Override
    public synchronized DiskShare getShare(String name) throws IOException {
        if (closed) {
            throw new IllegalStateException("Already closed");
        }

        return getShare(name, true);
    }

    private DiskShare getShare(String name, boolean retryOnTransportFailure) throws IOException {
        try {
            if (share == null || !share.isConnected()) {
                share = (DiskShare) getSession().connectShare(name);
            }

            return share;
        } catch (SMBRuntimeException e) {
            if (retryOnTransportFailure && e.getCause() instanceof TransportException) {
                closeSession();
                return getShare(name, false);
            }

            throw e;
        }
    }

    private Session getSession() throws IOException {
        if (session == null) {
            Connection connection = client.connect(host, port);
            session = connection.authenticate(context);
        }

        return session;
    }

    private void closeSession() {
        if (session != null) {
            // this will close the session, then connection - handling any suppressed exceptions, etc.
            try (Connection c = session.getConnection();
                 Session s = session) {
                // no-op, just to trigger close() on both
            } catch (IOException ignored) {
                // best-effort cleanup before reconnecting
            } finally {
                session = null;
                share = null;
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        closed = true;
        try {
            closeSession();
        } finally {
            client.close();
        }
    }
}
