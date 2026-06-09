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

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

import java.io.IOException;

class ShareSourceImpl implements ShareSource {

    private final SMBClient client;
    private final String host;
    private final int port;
    private final AuthenticationContext context;

    private volatile boolean closed = false;

    ShareSourceImpl(SMBClient client, String host, int port, AuthenticationContext context) {
        this.client = client;
        this.host = host;
        this.port = port;
        this.context = context;
    }

    @Override
    public Holder open(String name) throws IOException {
        if (closed) {
            throw new IllegalStateException("Already closed");
        }

        Connection connection = client.connect(host, port);
        Session session = connection.authenticate(context);

        return new HolderImpl((DiskShare) session.connectShare(name));
    }

    @Override
    public void close() throws IOException {
        closed = true;
    }

    private static class HolderImpl implements Holder {

        private final DiskShare share;

        private HolderImpl(DiskShare share) {
            this.share = share;
        }

        @Override
        public DiskShare share() {
            return share;
        }

        @Override
        public void close() throws IOException {
            try (Connection c = share.getTreeConnect().getSession().getConnection();
                Session s = share.getTreeConnect().getSession()) {

                share.close();
            }
        }
    }
}
