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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2] 2.2.30 SMB2 CANCEL Request
 */
public class SMB2CancelRequest extends SMB2Packet {

    public SMB2CancelRequest(SMB2Dialect dialect, long messageId, long asyncId) {
        super(4, dialect, SMB2MessageCommandCode.SMB2_CANCEL);
        header.setMessageId(messageId);
        if (asyncId != 0) {
            header.setFlag(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND);
            header.setAsyncId(asyncId);
        }
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putReserved2(); // Reserved (2 bytes)
    }
}
