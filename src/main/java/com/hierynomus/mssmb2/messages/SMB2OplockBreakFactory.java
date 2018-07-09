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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Arrays;

public class SMB2OplockBreakFactory{

    public SMB2OplockBreak read(SMBBuffer buffer) throws Buffer.BufferException {
        // 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification
        // If the MessageId field of the SMB2 header of the response is 0xFFFFFFFFFFFFFFFF,
        // this MUST be
        // processed as an oplock break indication.
        buffer.skip(24);
        byte[] messageId = buffer.readRawBytes(8);
        buffer.rpos(0);
        final boolean isBreakNotification = Arrays.equals(messageId, (new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));

        // TODO: Use structureSize as well to determine oplock and lease.
        // buffer.skip(64);
        // final int structureSize = buffer.readUInt16();
        // buffer.rpos(0);

        if(isBreakNotification) {
            return read(new SMB2OplockBreakNotification(), buffer);
        }else {
            return read(new SMB2OplockBreakAcknowledgmentResponse(), buffer);
        }
    }

    private SMB2OplockBreak read(SMB2OplockBreak packet, SMBBuffer buffer) throws Buffer.BufferException {
        packet.read(buffer);
        return packet;
    }

}
