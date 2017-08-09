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
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fsctl.FsCtlPipeWaitRequest;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;

import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class PipeShare extends Share {
    private static final int FSCTL_PIPE_WAIT = 0x00110018;

    public PipeShare(SmbPath smbPath, TreeConnect treeConnect) {
        super(smbPath, treeConnect);
    }

    /**
     * Requests that the server wait until an instance of the specified named pipe is available for connection.
     * <p>
     * Name must not include the "\pipe\", so if the operation was on \\server\pipe\pipename, the name would be "pipename".
     * <p>
     * This method requests that the server wait indefinitely. To specify a maximum wait time use {@link #waitForPipe(String, long, TimeUnit)}.
     *
     * @param name the name of the named pipe.
     * @return true if an instance of the pipe is available; false if a timeout occurred
     * @throws SMBApiException if an error occurs while waiting for an instance of the pipe to become available
     */
    public boolean waitForPipe(String name) {
        return waitForPipe(name, 0, TimeUnit.MILLISECONDS);
    }

    /**
     * Requests that the server wait until an instance of the specified named pipe is available for connection.
     * <p>
     * Name must not include the "\pipe\", so if the operation was on \\server\pipe\pipename, the name would be "pipename".
     *
     * @param name        the name of the named pipe.
     * @param timeout     the amount of time to wait until an instance is available
     * @param timeoutUnit the unit in which timeout is specified
     * @return true if an instance of the pipe is available; false if a timeout occurred
     * @throws SMBApiException if an error occurs while waiting for an instance of the pipe to become available
     */
    public boolean waitForPipe(String name, long timeout, TimeUnit timeoutUnit) {
        SMBBuffer buffer = new SMBBuffer();
        new FsCtlPipeWaitRequest(name, timeout, timeoutUnit, timeout > 0).write(buffer);

        Future<SMB2IoctlResponse> responseFuture = ioctlAsync(FSCTL_PIPE_WAIT, true, new ArrayByteChunkProvider(buffer.getCompactData(), 0));

        long timeoutMs;
        if (timeout > 0) {
            // Wait a little bit longer than the requested timeout to allow the server to respond with STATUS_IO_TIMEOUT
            timeoutMs = timeoutUnit.toMillis(timeout) + 20;
        } else {
            timeoutMs = 0;
        }

        SMB2IoctlResponse response = receive(responseFuture, timeoutMs);

        NtStatus status = response.getHeader().getStatus();
        switch (status) {
            case STATUS_SUCCESS:
                return true;
            case STATUS_IO_TIMEOUT:
                return false;
            default:
                throw new SMBApiException(response.getHeader(), "Error while waiting for pipe " + name);
        }
    }

    public NamedPipe open(String name, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponse response = createFile(name, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        return new NamedPipe(response.getFileId(), this, name);
    }

    public SMB2FileId openFileId(String path, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return super.openFileId(path, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions);
    }

    public void closeFileId(SMB2FileId fileId) throws SMBApiException {
        super.closeFileId(fileId);
    }
}
