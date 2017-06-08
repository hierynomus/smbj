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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.fileinformation.FileInformation;
import com.hierynomus.msfscc.fileinformation.FileInformationFactory;
import com.hierynomus.msfscc.fileinformation.FileRenameInformation;
import com.hierynomus.msfscc.fileinformation.FileSettableInformation;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBApiException;
import com.hierynomus.smbj.common.SMBRuntimeException;
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
import java.util.EnumSet;
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

        if ((this.accessMask & (AccessMask.GENERIC_READ.getValue() | AccessMask.FILE_READ_EA.getValue())) == 0) {
            throw new SMBApiException(
                NtStatus.STATUS_ACCESS_DENIED,
                NtStatus.STATUS_ACCESS_DENIED.getValue(),
                null,
                "The file is not open for reading"
            );
        }

        Session session = treeConnect.getSession();
        NegotiatedProtocol negotiatedProtocol = session.getConnection().getNegotiatedProtocol();

        int payloadSize = length < negotiatedProtocol.getMaxReadSize() ? length : negotiatedProtocol.getMaxReadSize();
        SMB2ReadRequest rreq = new SMB2ReadRequest(
            negotiatedProtocol.getDialect(),
            fileId,
            session.getSessionId(),
            treeConnect.getTreeId(),
            fileOffset,
            payloadSize
        );

        Future<SMB2ReadResponse> send = session.send(rreq);
        try {
            SMB2ReadResponse smb2Packet = send.get();
            if (smb2Packet.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(smb2Packet.getHeader(), "Read failed for " + this);
            }
            int read = smb2Packet.getDataLength();
            if (read > payloadSize) {
                read = payloadSize;
            }
            System.arraycopy(smb2Packet.getData(), 0, dst, 0, read);
            return read;
        } catch (InterruptedException | ExecutionException e) {
            throw new IOException(e);
        }
    }

    /**
     * Direct buffer write to the file
     *
     * @param src        source buffer to be  written
     * @param fileOffset offset where to start write
     * @param length     length of src buffer
     * @return bytes written
     * @throws IOException
     */
    public int write(final byte[] src, final int fileOffset, final int length) throws IOException {

        if ((this.accessMask & (AccessMask.GENERIC_WRITE.getValue() | AccessMask.FILE_WRITE_EA.getValue())) == 0) {
            throw new SMBApiException(
                NtStatus.STATUS_ACCESS_DENIED,
                NtStatus.STATUS_ACCESS_DENIED.getValue(),
                null,
                "The file is not open for writing"
            );
        }

        Session session = treeConnect.getSession();
        NegotiatedProtocol negotiatedProtocol = session.getConnection().getNegotiatedProtocol();

        ByteChunkProvider provider = new ByteChunkProvider() {
            int remaining = length;

            ByteChunkProvider withOffset(int offset) {
                this.offset = offset;
                return this;
            }

            @Override
            public boolean isAvailable() {
                return remaining > 0;
            }

            @Override
            protected int getChunk(byte[] chunk) throws IOException {
                int write = chunk.length;
                if (write > remaining) {
                    write = remaining;
                }
                System.arraycopy(src, length - remaining, chunk, 0, write);
                remaining -= write;

                return write;
            }

            @Override
            public int bytesLeft() {
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
            if (smb2WriteResponse.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(smb2WriteResponse.getHeader(), "Write failed for " + this);
            }
            Long write = smb2WriteResponse.getBytesWritten();
            return write.intValue();

        } catch (InterruptedException | ExecutionException e) {
            throw new IOException(e);
        }
    }

    public void rename(String newName)throws TransportException, SMBApiException {
        this.rename(newName, false);
    }

    public void rename(String newName, boolean replaceIfExist)throws TransportException, SMBApiException {
        this.rename(newName, replaceIfExist, 0);
    }

    public void rename(String newName, boolean replaceIfExist, long rootDirectory)throws TransportException, SMBApiException {
        FileRenameInformation renameInfo = new FileRenameInformation(replaceIfExist, rootDirectory, newName);
        this.setFileInformation(renameInfo);
    }

    /**
     * Get information for a given fileId
     **/
    private <F extends FileSettableInformation> void setFileInformation(F information) throws SMBApiException, TransportException {
        FileInformation.Encoder<F> encoder = FileInformationFactory.getEncoder(information);

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Buffer.DEFAULT_SIZE, Endian.LE);
        encoder.write(information, buffer);
        byte[] info = buffer.getCompactData();

        setInfoCommon(
            this.fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
            null,
            encoder.getInformationClass(),
            info
        );
    }

    private void setInfoCommon(
        SMB2FileId fileId,
        SMB2SetInfoRequest.SMB2InfoType infoType,
        EnumSet<SecurityInformation> securityInfo,
        FileInformationClass fileInformationClass,
        byte[] buffer)
        throws SMBApiException {

        Session session = treeConnect.getSession();
        Connection connection = session.getConnection();

        SMB2SetInfoRequest qreq = new SMB2SetInfoRequest(
            connection.getNegotiatedProtocol().getDialect(), session.getSessionId(), treeConnect.getTreeId(),
            infoType, fileId,
            fileInformationClass, securityInfo, buffer);
        try {
            Future<SMB2SetInfoResponse> qiResponseFuture = session.send(qreq);
            SMB2SetInfoResponse qresp = Futures.get(qiResponseFuture, SMBRuntimeException.Wrapper);

            if (qresp.getHeader().getStatus() != NtStatus.STATUS_SUCCESS) {
                throw new SMBApiException(qresp.getHeader(), "SET_INFO failed for " + fileId);
            }
        } catch (TransportException e) {
            throw SMBRuntimeException.Wrapper.wrap(e);
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
