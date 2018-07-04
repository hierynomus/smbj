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

import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.Check;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.Arrays;

public class SMB2MessageConverter implements PacketFactory<SMB2Packet> {

    private SMB2Packet read(SMBBuffer buffer) throws Buffer.BufferException {
        // Check we see a valid header start
        Check.ensureEquals(buffer.readRawBytes(4), new byte[]{(byte) 0xFE, 'S', 'M', 'B'}, "Could not find SMB2 Packet header");
        // Skip until Command
        buffer.skip(8);
        SMB2MessageCommandCode command = SMB2MessageCommandCode.lookup(buffer.readUInt16());
        // Reset read position so that the message works.
        buffer.rpos(0);
        switch (command) {
            case SMB2_NEGOTIATE:
                return read(new SMB2NegotiateResponse(), buffer);
            case SMB2_SESSION_SETUP:
                return read(new SMB2SessionSetup(), buffer);
            case SMB2_TREE_CONNECT:
                return read(new SMB2TreeConnectResponse(), buffer);
            case SMB2_TREE_DISCONNECT:
                return read(new SMB2TreeDisconnect(), buffer);
            case SMB2_LOGOFF:
                return read(new SMB2Logoff(), buffer);
            case SMB2_CREATE:
                return read(new SMB2CreateResponse(), buffer);
            case SMB2_CHANGE_NOTIFY:
                return read(new SMB2ChangeNotifyResponse(), buffer);
            case SMB2_QUERY_DIRECTORY:
                return read(new SMB2QueryDirectoryResponse(), buffer);
            case SMB2_ECHO:
                return read(new SMB2Echo(), buffer);
            case SMB2_READ:
                return read(new SMB2ReadResponse(), buffer);
            case SMB2_CLOSE:
                return read(new SMB2Close(), buffer);
            case SMB2_FLUSH:
                return read(new SMB2Flush(), buffer);
            case SMB2_WRITE:
                return read(new SMB2WriteResponse(), buffer);
            case SMB2_IOCTL:
                return read(new SMB2IoctlResponse(), buffer);
            case SMB2_QUERY_INFO:
                return read(new SMB2QueryInfoResponse(), buffer);
            case SMB2_SET_INFO:
                return read(new SMB2SetInfoResponse(), buffer);
            case SMB2_OPLOCK_BREAK:
                // 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification
                // If the MessageId field of the SMB2 header of the response is 0xFFFFFFFFFFFFFFFF,
                // this MUST be
                // processed as an oplock break indication.
                buffer.skip(24);
                byte[] messageId = buffer.readRawBytes(8);
                buffer.rpos(0);
                if(Arrays.equals(messageId, (new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}))) {
                    return read(new SMB2OplockBreakNotification(), buffer);
                } else {
                    return read(new SMB2OplockBreakAcknowledgmentResponse(), buffer);
                }
            case SMB2_LOCK:
            case SMB2_CANCEL:
            default:
                throw new SMBRuntimeException("Unknown SMB2 Message Command type: " + command);

        }
    }

    private SMB2Packet read(SMB2Packet packet, SMBBuffer buffer) throws Buffer.BufferException {
        packet.read(buffer);
        return packet;
    }

    @Override
    public SMB2Packet read(byte[] data) throws Buffer.BufferException {
        return read(new SMBBuffer(data));
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data[0] == (byte) 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }
}
