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

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;

/**
 * [MS-FSCC] 2.3.28 FSCTL_PIPE_PEEK Reply
 */
public class FsCtlPipePeekResponse {
    public static final int STRUCTURE_SIZE = 24;

    private PipeState state;
    private long readDataAvailable;
    private long numberOfMessages;
    private long messageLength;
    private byte[] data;

    public FsCtlPipePeekResponse() {
    }

    public FsCtlPipePeekResponse(PipeState state, long readDataAvailable, long numberOfMessages, long messageLength, byte[] data) {
        this.state = state;
        this.readDataAvailable = readDataAvailable;
        this.numberOfMessages = numberOfMessages;
        this.messageLength = messageLength;
        this.data = data;
    }

    public PipeState getState() {
        return state;
    }

    public long getReadDataAvailable() {
        return readDataAvailable;
    }

    public long getNumberOfMessages() {
        return numberOfMessages;
    }

    public long getMessageLength() {
        return messageLength;
    }

    public byte[] getData() {
        return data;
    }

    public void read(Buffer buffer) {
        state = EnumWithValue.EnumUtils.valueOf(buffer.readUInt32(), PipeState.class, null);
        readDataAvailable = buffer.readUInt32();
        numberOfMessages = buffer.readUInt32();
        messageLength = buffer.readUInt32();
        data = buffer.readRawBytes(buffer.available());
    }

    public enum PipeState implements EnumWithValue<PipeState> {
        FILE_PIPE_CONNECTED_STATE(0x00000003),
        FILE_PIPE_CLOSING_STATE(0x00000004);

        private final int value;

        PipeState(int value) {
            this.value = value;
        }

        @Override
        public long getValue() {
            return value;
        }
    }
}
