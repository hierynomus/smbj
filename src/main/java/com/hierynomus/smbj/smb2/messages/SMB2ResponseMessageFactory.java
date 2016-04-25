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
package com.hierynomus.smbj.smb2.messages;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.Check;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2MessageCommandCode;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.transport.TransportException;

public class SMB2ResponseMessageFactory {

    public static SMB2Packet read(SMBBuffer buffer) throws Buffer.BufferException, TransportException {
        // Check we see a valid header start
        Check.ensureEquals(buffer.readRawBytes(4), new byte[] {(byte) 0xFE, 'S', 'M', 'B'}, "Could not find SMB2 Packet header");
        // Skip until Command
        buffer.skip(8);
        SMB2MessageCommandCode command = SMB2MessageCommandCode.lookup(buffer.readUInt16());
        // Reset read position so that the message works.
        buffer.rpos(0);
        switch (command) {
            case SMB2_NEGOTIATE:
                return new SMB2NegotiateResponse().read(buffer);
            case SMB2_SESSION_SETUP:
                return new SMB2SessionSetup().read(buffer);
            case SMB2_TREE_CONNECT:
                return new SMB2TreeConnectResponse().read(buffer);
            case SMB2_TREE_DISCONNECT:
                return new SMB2TreeDisconnect().read(buffer);
            case SMB2_LOGOFF:
                return new SMB2Logoff().read(buffer);
            case SMB2_CREATE:
                return new SMB2CreateResponse().read(buffer);
            case SMB2_CHANGE_NOTIFY:
                return new SMB2ChangeNotifyResponse().read(buffer);
            case SMB2_QUERY_DIRECTORY:
                return new SMB2QueryDirectoryResponse().read(buffer);
            case SMB2_ECHO:
                return new SMB2Echo().read(buffer);
            case SMB2_READ:
                return new SMB2ReadResponse().read(buffer);
            case SMB2_CLOSE:
                return new SMB2Close().read(buffer);
            case SMB2_FLUSH:
                return new SMB2Flush().read(buffer);
            case SMB2_WRITE:
                return new SMB2WriteResponse().read(buffer);
            case SMB2_IOCTL:
                return new SMB2IoctlResponse().read(buffer);
            case SMB2_QUERY_INFO:
                return new SMB2QueryInfoResponse().read(buffer);
            case SMB2_SET_INFO:
                return new SMB2SetInfoResponse().read(buffer);
            case SMB2_LOCK:
            case SMB2_CANCEL:
            case SMB2_OPLOCK_BREAK:
            default:
                throw new TransportException("Unknown SMB2 Message Command type: " + command);

        }
    }
}
