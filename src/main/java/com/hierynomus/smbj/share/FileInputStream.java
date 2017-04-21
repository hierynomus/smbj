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
package com.hierynomus.smbj.share;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Future;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;

public class FileInputStream extends InputStream {

    protected TreeConnect treeConnect;
    private Session session;
    private Connection connection;
    private SMB2FileId fileId;
    private long offset = 0;
    private int curr = 0;
    private byte[] buf;
    private ProgressListener progressListener;
    private boolean isClosed;
    private Future<SMB2ReadResponse> nextResponse;

    private static final Logger logger = LoggerFactory.getLogger(FileInputStream.class);

    public FileInputStream(File file, ProgressListener progressListener) {
        this.treeConnect = file.treeConnect;
        this.fileId = file.fileId;
        this.session = treeConnect.getSession();
        this.connection = session.getConnection();
        this.progressListener = progressListener;
    }

    @Override
    public int read() throws IOException {
        if (buf == null || curr >= buf.length) {
            loadBuffer();
        }
        if (isClosed) return -1;
        ++curr;
        return buf[curr - 1] & 0xFF;
    }

    @Override
    public int read(byte b[]) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte b[], int off, int len) throws IOException {
        if (buf == null || curr >= buf.length) {
            loadBuffer();
        }
        if (isClosed) return -1;
        int l = buf.length - curr > len ? len : buf.length - curr;
        System.arraycopy(buf, curr, b, off, l);
        curr = curr + l;
        return l;
    }

    @Override
    public void close() throws IOException {
        isClosed = true;
        session = null;
        connection = null;
        buf = null;
    }

    @Override
    public int available() throws IOException {
        throw new IOException("Available not supported");
    }

    private void loadBuffer() throws IOException {

        if (nextResponse == null)
            nextResponse = sendRequest();

        SMB2ReadResponse res = Futures.get(nextResponse, TransportException.Wrapper);
        if (res.getHeader().getStatus() == NtStatus.STATUS_SUCCESS) {
            buf = res.getData();
            curr = 0;
            offset += res.getDataLength();
            if (progressListener != null) progressListener.onProgressChanged(offset, -1);
        }
        if (res.getHeader().getStatus() == NtStatus.STATUS_END_OF_FILE) {
            logger.debug("EOF, {} bytes read", offset);
            isClosed = true;
            return;
        }
        if (res.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
            throw new SMBApiException(res.getHeader(), "Read failed for " + this);
        }
        nextResponse = sendRequest();
    }

    private Future<SMB2ReadResponse> sendRequest() throws IOException {
        NegotiatedProtocol negotiatedProtocol = connection.getNegotiatedProtocol();
        SMB2ReadRequest rreq = new SMB2ReadRequest(negotiatedProtocol.getDialect(), fileId,
            session.getSessionId(), treeConnect.getTreeId(), offset, negotiatedProtocol.getMaxReadSize());
        return session.send(rreq);
    }
}
