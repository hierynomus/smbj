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
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileInformationClass;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.smbj.io.EmptyByteChunkProvider;
import com.hierynomus.smbj.session.Session;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class Share implements AutoCloseable {
    private static final SMB2FileId ROOT_ID = new SMB2FileId(
        new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
        new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}
    );

    private static final StatusHandler SUCCESS_OR_SYMLINK = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == NtStatus.STATUS_SUCCESS.getValue() ||
                statusCode == NtStatus.STATUS_STOPPED_ON_SYMLINK.getValue();
        }
    };
    private static final StatusHandler SUCCESS_OR_NO_MORE_FILES_OR_NO_SUCH_FILE = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == NtStatus.STATUS_SUCCESS.getValue() ||
                statusCode == NtStatus.STATUS_NO_MORE_FILES.getValue() ||
                statusCode == NtStatus.STATUS_NO_SUCH_FILE.getValue();
        }
    };
    private static final StatusHandler SUCCESS_OR_EOF = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == NtStatus.STATUS_SUCCESS.getValue() ||
                statusCode == NtStatus.STATUS_END_OF_FILE.getValue();
        }
    };
    private static final StatusHandler SUCCESS_OR_CLOSED = new StatusHandler() {
        @Override
        public boolean isSuccess(long statusCode) {
            return statusCode == NtStatus.STATUS_SUCCESS.getValue() ||
                statusCode == NtStatus.STATUS_FILE_CLOSED.getValue();
        }
    };

    protected final SmbPath smbPath;
    protected final TreeConnect treeConnect;
    private final long treeId;
    protected Session session;
    private final SMB2Dialect dialect;
    private final int readBufferSize;
    private final long readTimeout;
    private final int writeBufferSize;
    private final long writeTimeout;
    private final int transactBufferSize;
    private final long transactTimeout;
    private final long sessionId;
    private final AtomicBoolean disconnected = new AtomicBoolean(false);

    Share(SmbPath smbPath, TreeConnect treeConnect) {
        this.smbPath = smbPath;
        this.treeConnect = treeConnect;
        session = treeConnect.getSession();
        Connection connection = treeConnect.getConnection();
        NegotiatedProtocol negotiatedProtocol = connection.getNegotiatedProtocol();
        dialect = negotiatedProtocol.getDialect();
        SmbConfig config = connection.getConfig();
        readBufferSize = Math.min(config.getReadBufferSize(), negotiatedProtocol.getMaxReadSize());
        readTimeout = config.getReadTimeout();
        writeBufferSize = Math.min(config.getWriteBufferSize(), negotiatedProtocol.getMaxWriteSize());
        writeTimeout = config.getWriteTimeout();
        transactBufferSize = Math.min(config.getTransactBufferSize(), negotiatedProtocol.getMaxTransactSize());
        transactTimeout = config.getTransactTimeout();
        sessionId = session.getSessionId();
        treeId = treeConnect.getTreeId();
    }

    @Override
    public void close() throws IOException {
        if (!disconnected.getAndSet(true)) {
            treeConnect.close();
        }
    }

    public boolean isConnected() {
        return !disconnected.get();
    }

    public SmbPath getSmbPath() {
        return smbPath;
    }

    public TreeConnect getTreeConnect() {
        return treeConnect;
    }

    int getReadBufferSize() {
        return readBufferSize;
    }

    long getReadTimeout() {
        return readTimeout;
    }

    int getWriteBufferSize() {
        return writeBufferSize;
    }

    SMB2FileId openFileId(SmbPath path, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return createFile(path, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions).getFileId();
    }

    SMB2CreateResponse createFile(SmbPath path, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateRequest cr = new SMB2CreateRequest(
            dialect,
            sessionId, treeId,
            impersonationLevel,
            accessMask,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            path
        );
        SMB2CreateResponse resp = sendReceive(cr, "Create", path, getCreateStatusHandler(), transactTimeout);
        return resp;
    }

    protected StatusHandler getCreateStatusHandler() {
        return SUCCESS_OR_SYMLINK;
    }

    void flush(SMB2FileId fileId) throws SMBApiException {
        SMB2Flush flushReq = new SMB2Flush(
            dialect,
            fileId,
            sessionId, treeId
        );
        sendReceive(flushReq, "Flush", fileId, StatusHandler.SUCCESS, writeTimeout);
    }

    void closeFileId(SMB2FileId fileId) throws SMBApiException {
        SMB2Close closeReq = new SMB2Close(dialect, sessionId, treeId, fileId);
        sendReceive(closeReq, "Close", fileId, SUCCESS_OR_CLOSED, transactTimeout);
    }

    void closeFileIdNoWait(SMB2FileId fileId) throws SMBApiException {
        SMB2Close closeReq = new SMB2Close(dialect, sessionId, treeId, fileId);
        send(closeReq);
    }

    SMB2QueryInfoResponse queryInfo(SMB2FileId fileId, SMB2QueryInfoRequest.SMB2QueryInfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, FileSystemInformationClass fileSystemInformationClass) {
        SMB2QueryInfoRequest qreq = new SMB2QueryInfoRequest(
            dialect,
            sessionId, treeId,
            fileId, infoType,
            fileInformationClass, fileSystemInformationClass, null, securityInfo
        );
        return sendReceive(qreq, "QueryInfo", fileId, StatusHandler.SUCCESS, transactTimeout);
    }

    void setInfo(SMB2FileId fileId, SMB2SetInfoRequest.SMB2InfoType infoType, Set<SecurityInformation> securityInfo, FileInformationClass fileInformationClass, byte[] buffer) {
        SMB2SetInfoRequest qreq = new SMB2SetInfoRequest(
            dialect,
            sessionId, treeId,
            infoType, fileId,
            fileInformationClass, securityInfo, buffer
        );
        sendReceive(qreq, "SetInfo", fileId, StatusHandler.SUCCESS, transactTimeout);
    }

    SMB2QueryDirectoryResponse queryDirectory(SMB2FileId fileId, Set<SMB2QueryDirectoryRequest.SMB2QueryDirectoryFlags> flags, FileInformationClass informationClass, String searchPattern) {
        SMB2QueryDirectoryRequest qdr = new SMB2QueryDirectoryRequest(
            dialect,
            sessionId, treeId,
            fileId, informationClass,
            flags,
            0,
            searchPattern,
            transactBufferSize
        );

        return sendReceive(qdr, "Query directory", fileId, SUCCESS_OR_NO_MORE_FILES_OR_NO_SUCH_FILE, transactTimeout);
    }

    SMB2WriteResponse write(SMB2FileId fileId, ByteChunkProvider provider) {
        SMB2WriteRequest wreq = new SMB2WriteRequest(
            dialect,
            fileId,
            sessionId, treeId,
            provider,
            writeBufferSize
        );
        return sendReceive(wreq, "Write", fileId, StatusHandler.SUCCESS, writeTimeout);
    }

    SMB2ReadResponse read(SMB2FileId fileId, long offset, int length) {
        return receive(
            readAsync(fileId, offset, length),
            "Read",
            fileId,
            SUCCESS_OR_EOF,
            readTimeout
        );
    }

    Future<SMB2ReadResponse> readAsync(SMB2FileId fileId, long offset, int length) {
        SMB2ReadRequest rreq = new SMB2ReadRequest(
            dialect,
            fileId,
            sessionId, treeId,
            offset,
            Math.min(length, readBufferSize)
        );
        return send(rreq);
    }

    private static final EmptyByteChunkProvider EMPTY = new EmptyByteChunkProvider(0);

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode the control code
     * @param isFsCtl true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData  the control code dependent input data
     * @return the response data or <code>null</code> if the control code did not produce a response
     */
    public byte[] ioctl(long ctlCode, boolean isFsCtl, byte[] inData) {
        return ioctl(ROOT_ID, ctlCode, isFsCtl, inData, 0, inData.length);
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode  the control code
     * @param isFsCtl  true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData   the control code dependent input data
     * @param inOffset the offset in <code>inData</code> where the input data starts
     * @param inLength the number of bytes from <code>inData</code> to send, starting at <code>offset</code>
     * @return the response data or <code>null</code> if the control code did not produce a response
     */
    public byte[] ioctl(long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength) {
        return ioctl(ROOT_ID, ctlCode, isFsCtl, inData, inOffset, inLength);
    }

    /**
     * Sends a control code directly to a specified device driver, causing the corresponding device to perform the
     * corresponding operation.
     *
     * @param ctlCode   the control code
     * @param isFsCtl   true if the control code is an FSCTL; false if it is an IOCTL
     * @param inData    the control code dependent input data
     * @param inOffset  the offset in <code>inData</code> where the input data starts
     * @param inLength  the number of bytes from <code>inData</code> to send, starting at <code>inOffset</code>
     * @param outData   the buffer where the response data should be written
     * @param outOffset the offset in <code>outData</code> where the output data should be written
     * @param outLength the maximum amount of data to write in <code>outData</code>, starting at <code>outOffset</code>
     * @return the number of bytes written to <code>outData</code>
     */
    public int ioctl(long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength, byte[] outData, int outOffset, int outLength) {
        return ioctl(ROOT_ID, ctlCode, isFsCtl, inData, inOffset, inLength, outData, outOffset, outLength);
    }

    byte[] ioctl(SMB2FileId fileId, long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength) {
        return ioctl(fileId, ctlCode, isFsCtl, inData, inOffset, inLength, -1);
    }

    byte[] ioctl(SMB2FileId fileId, long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength, int maxOutputResponse) {
        SMB2IoctlResponse response = ioctl(fileId, ctlCode, isFsCtl, new ArrayByteChunkProvider(inData, inOffset, inLength, 0), maxOutputResponse);
        return response.getOutputBuffer();
    }

    int ioctl(SMB2FileId fileId, long ctlCode, boolean isFsCtl, byte[] inData, int inOffset, int inLength, byte[] outData, int outOffset, int outLength) {
        SMB2IoctlResponse response = ioctl(fileId, ctlCode, isFsCtl, new ArrayByteChunkProvider(inData, inOffset, inLength, 0), outLength);
        int length = 0;
        if (outData != null) {
            byte[] outputBuffer = response.getOutputBuffer();
            length = Math.min(outLength, outputBuffer.length);
            System.arraycopy(outputBuffer, 0, outData, outOffset, length);
        }
        return length;
    }

    SMB2IoctlResponse ioctl(SMB2FileId fileId, long ctlCode, boolean isFsCtl, ByteChunkProvider inputData, int maxOutputResponse) {
        Future<SMB2IoctlResponse> fut = ioctlAsync(fileId, ctlCode, isFsCtl, inputData, maxOutputResponse);
        return receive(fut, "IOCTL", fileId, StatusHandler.SUCCESS, transactTimeout);
    }

    public Future<SMB2IoctlResponse> ioctlAsync(long ctlCode, boolean isFsCtl, ByteChunkProvider inputData) {
        return ioctlAsync(ROOT_ID, ctlCode, isFsCtl, inputData, -1);
    }

    Future<SMB2IoctlResponse> ioctlAsync(SMB2FileId fileId, long ctlCode, boolean isFsCtl, ByteChunkProvider inputData, int maxOutputResponse) {
        ByteChunkProvider inData = inputData == null ? EMPTY : inputData;

        if (inData.bytesLeft() > transactBufferSize) {
            throw new SMBRuntimeException("Input data size exceeds maximum allowed by server: " + inData.bytesLeft() + " > " + transactBufferSize);
        }

        int maxResponse;
        if (maxOutputResponse < 0) {
            maxResponse = transactBufferSize;
        } else if (maxOutputResponse > transactBufferSize) {
            throw new SMBRuntimeException("Output data size exceeds maximum allowed by server: " + maxOutputResponse + " > " + transactBufferSize);
        } else {
            maxResponse = maxOutputResponse;
        }

        SMB2IoctlRequest ioreq = new SMB2IoctlRequest(dialect, sessionId, treeId, ctlCode, fileId, inData, isFsCtl, maxResponse);
        return send(ioreq);
    }

    private <T extends SMB2Packet> T sendReceive(SMB2Packet request, String name, Object target, StatusHandler statusHandler, long timeout) {
        Future<T> fut = send(request);
        return receive(fut, name, target, statusHandler, timeout);
    }

    private <T extends SMB2Packet> Future<T> send(SMB2Packet request) {
        if (!isConnected()) {
            throw new SMBRuntimeException(getClass().getSimpleName() + " has already been closed");
        }

        try {
            return session.send(request);
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }

    <T extends SMB2Packet> T receive(Future<T> fut, String name, Object target, StatusHandler statusHandler, long timeout) {
        T resp = receive(fut, timeout);

        long status = resp.getHeader().getStatusCode();
        if (!statusHandler.isSuccess(status)) {
            throw new SMBApiException(resp.getHeader(), name + " failed for " + target);
        }
        return resp;
    }

    <T extends SMB2Packet> T receive(Future<T> fut, long timeout) {
        T resp;
        try {
            if (timeout > 0) {
                resp = Futures.get(fut, timeout, TimeUnit.MILLISECONDS, TransportException.Wrapper);
            } else {
                resp = Futures.get(fut, TransportException.Wrapper);
            }
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
        return resp;
    }
}
