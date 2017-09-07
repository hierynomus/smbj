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
package com.hierynomus.mssmb2;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.smbj.common.SMBRuntimeException;

public class SMBApiException extends SMBRuntimeException {
    private final NtStatus status;
    private final SMB2MessageCommandCode failedCommand;
    private long statusCode;

    public SMBApiException(NtStatus status, SMB2MessageCommandCode failedCommand, Throwable t) {
        super(t);
        this.status = status;
        this.statusCode = status.getValue();
        this.failedCommand = failedCommand;
    }

    public SMBApiException(SMB2Header header, String message) {
        super(message);
        this.status = header.getStatus();
        this.statusCode = header.getStatusCode();
        this.failedCommand = header.getMessage();
    }

    public SMBApiException(SMB2Header header, String message, Throwable t) {
        super(message, t);
        this.status = header.getStatus();
        this.statusCode = header.getStatusCode();
        this.failedCommand = header.getMessage();
    }

    public NtStatus getStatus() {
        return status;
    }

    public long getStatusCode() {
        return statusCode;
    }

    public SMB2MessageCommandCode getFailedCommand() {
        return failedCommand;
    }

    @Override
    public String getMessage() {
        return status + "(" + status.getValue() + "/" + statusCode + "): " + super.getMessage();
    }
}
