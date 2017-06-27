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
package com.hierynomus.msfscc.fsctl;

import com.hierynomus.protocol.commons.buffer.Buffer;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * [MS-FSCC] 2.3.29 FSCTL_PIPE_WAIT Request
 */
public class FsCtlPipeWaitRequest {
    private final TimeUnit timeoutUnit;
    private String name;
    private long timeout;
    private boolean timeoutSpecified;

    public FsCtlPipeWaitRequest(String name, long timeout, TimeUnit timeoutUnit, boolean timeoutSpecified) {
        this.name = name;

        this.timeout = timeout;
        this.timeoutUnit = timeoutUnit;

        this.timeoutSpecified = timeoutSpecified;
    }

    public String getName() {
        return name;
    }

    public long getTimeout() {
        return timeout;
    }

    public TimeUnit getTimeoutUnit() {
        return timeoutUnit;
    }

    public void write(Buffer buffer) {
        // Timeout (8 bytes): A 64-bit signed integer that specifies the maximum amount of time, in units of
        // 100 milliseconds, that the function can wait for an instance of the named pipe to be available.
        buffer.putUInt64(timeoutSpecified ? timeoutUnit.toMillis(timeout) / 100L : 0L);

        // NameLength (4 bytes): A 32-bit unsigned integer that specifies the size, in bytes, of the named pipe Name
        // field.
        int nameLengthPos = buffer.wpos();
        buffer.putUInt32(0);

        // TimeoutSpecified (1 byte): A Boolean (section 2.1.8) value that specifies whether or not the Timeout
        // parameter will be ignored.
        buffer.putBoolean(timeoutSpecified);

        // Padding (1 byte): The client SHOULD set this field to 0x00, and the server MUST ignore it.
        buffer.putByte((byte) 0);

        // Name (variable): A Unicode string that contains the name of the named pipe. Name MUST not include the
        // "\pipe\", so if the operation was on \\server\pipe\pipename, the name would be "pipename".
        int nameStartPos = buffer.wpos();
        buffer.putString(name, StandardCharsets.UTF_16);

        int endPos = buffer.wpos();
        buffer.wpos(nameLengthPos);
        buffer.putUInt32(endPos - nameStartPos);
        buffer.wpos(endPos);
    }
}
