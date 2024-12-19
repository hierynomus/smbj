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

import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

import java.io.IOException;

class ShareSourceImpl implements ShareSource {

    private final Session session;

    private volatile boolean closed = false;

    ShareSourceImpl(Session session) {
        this.session = session;
    }

    @Override
    public Holder open(String name) {
        if (closed)
            throw new IllegalStateException("Already closed");

        return new HolderImpl((DiskShare) session.connectShare(name));
    }

    @Override
    public void close() throws IOException {
        try (Connection c = session.getConnection();
             Session s = session) {

            closed = true;
        }
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
            share.close();
        }
    }
}
