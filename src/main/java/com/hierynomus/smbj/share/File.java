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
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutionException;
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
            Future<SMB2WriteResponse> writeFuture = session.send(wreq);
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


    /**
     * Direct buffer read from the file
     *
     * @param dst        source buffer to be  written
     * @param fileOffset offset where to start read
     * @param length     length of src buffer
     * @return bytes readed
     * @throws IOException
     */
    public int read(byte[] dst, int fileOffset, int length) throws IOException {
        NegotiatedProtocol negotiatedProtocol = treeConnect.getSession().getConnection().getNegotiatedProtocol();

        SMB2ReadRequest rreq = new SMB2ReadRequest(
            negotiatedProtocol.getDialect(),
            fileId,
            treeConnect.getSession().getSessionId(),
            treeConnect.getTreeId(),
            fileOffset,
            length < negotiatedProtocol.getMaxReadSize()? length : negotiatedProtocol.getMaxReadSize()
        );

        Future<SMB2ReadResponse> send = treeConnect.getSession().send(rreq);
        try {
            SMB2ReadResponse smb2Packet = send.get();
            int read = smb2Packet.getDataLength();
            System.arraycopy(smb2Packet.getData(), 0, dst, 0, read);
            return read;
        } catch (InterruptedException e) {
            throw new IOException(e);
        } catch (ExecutionException e) {
            throw new IOException(e);
        }
    }

    /**
     * Direct buffer write to the file
     *
     * @param src        source buffer to be  written
     * @param fileOffset offset where to start write
     * @param lenght     length of src buffer
     * @return bytes written
     * @throws IOException
     */
    public int write(final byte[] src, final int fileOffset, final int lenght) throws IOException {
        Session session = treeConnect.getSession();
        NegotiatedProtocol negotiatedProtocol = treeConnect.getSession().getConnection().getNegotiatedProtocol();

        ByteChunkProvider provider = new ByteChunkProvider()
        {
            int remaining = lenght;

            public ByteChunkProvider withOffset(int offset){
                this.offset = offset;
                return this;
            }

            @Override
            public boolean isAvailable()
            {
                return remaining > 0;
            }

            @Override
            protected int getChunk(byte[] chunk) throws IOException
            {
                int write = chunk.length;
                if (write > remaining) {
                    write = remaining;
                }
                System.arraycopy(src, lenght - remaining, chunk, 0, write);
                remaining -= write;

                return write;
            }

            @Override
            public int bytesLeft()
            {
                return remaining;
            }
        }.withOffset(fileOffset);

        SMB2WriteRequest wreq = new SMB2WriteRequest(
            negotiatedProtocol.getDialect(),
            fileId,
            session.getSessionId(),
            treeConnect.getTreeId(),
            provider,
            negotiatedProtocol.getMaxWriteSize()
        );
        logger.trace("Sending {} for file {}, byte offset {}, bytes available {}", wreq, treeConnect.getHandle().smbPath, provider.getOffset(),
                     provider.bytesLeft());
        Future<SMB2WriteResponse> writeFuture = session.send(wreq);
        try {
            SMB2WriteResponse smb2WriteResponse = writeFuture.get();
            Long write = smb2WriteResponse.getBytesWritten();
            if (smb2WriteResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(smb2WriteResponse.getHeader(), "Write failed for " + this);
            }
            return write.intValue();

        } catch (InterruptedException e) {
            throw new IOException(e);
        } catch (ExecutionException e) {
            throw new IOException(e);
        }
    }

    @Override
    public String toString() {
        return "File{" +
            "fileId=" + fileId +
            ", fileName='" + fileName + '\'' +
            '}';
    }
}
