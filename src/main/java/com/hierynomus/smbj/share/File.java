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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Future;

public class File extends DiskEntry {

    private static final Logger logger = LoggerFactory.getLogger(File.class);
    private final long accessMask;

    public File(SMB2FileId fileId, TreeConnect treeConnect, String fileName, long accessMask) {
        super(treeConnect, fileId, fileName);
        this.accessMask = accessMask;
    }

    public void write(ByteChunkProvider provider, ProgressListener progressListener) throws TransportException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        while (provider.isAvailable()) {
            logger.debug("Writing to {} from offset {}", this.fileName, provider.getOffset());
            SMB2WriteRequest wreq = new SMB2WriteRequest(connection.getNegotiatedProtocol().getDialect(), getFileId(),
                session.getSessionId(), treeConnect.getTreeId(), provider, connection.getNegotiatedProtocol().getMaxWriteSize());
            Future<SMB2WriteResponse> writeFuture = connection.send(wreq);
            SMB2WriteResponse wresp = Futures.get(writeFuture, TransportException.Wrapper);
            if (wresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(wresp.getHeader(), "Write failed for " + this);
            }
            if (progressListener != null) progressListener.onProgressChanged(wresp.getBytesWritten(), provider.getOffset());
        }
    }

    public void write(ByteChunkProvider provider) throws IOException {
        write(provider, null);
    }

    public void read(OutputStream destStream) throws IOException {
        read(destStream, null);
    }

    public void read(OutputStream destStream, ProgressListener progressListener) throws IOException {
        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();
        InputStream is = getInputStream(progressListener);
        int numRead = -1;
        byte[] buf = new byte[connection.getNegotiatedProtocol().getMaxWriteSize()];
        while ((numRead = is.read(buf)) != -1) {
            destStream.write(buf, 0, numRead);
        }
        is.close();
    }

    public InputStream getInputStream() {
        return getInputStream(null);
    }

    private InputStream getInputStream(final ProgressListener listener) {
        return new FileInputStream(this, listener);
    }

    public OutputStream getOutputStream() {
        return getOutputStream(null);
    }

    public OutputStream getOutputStream(final ProgressListener listener) {
        return new FileOutputStream(this, listener);
    }

    @Override
    public String toString() {
        return "File{" +
                "fileId=" + fileId +
                ", fileName='" + fileName + '\'' +
                '}';
    }
}
