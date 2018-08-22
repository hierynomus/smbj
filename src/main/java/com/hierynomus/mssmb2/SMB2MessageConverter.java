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
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.common.SMBRuntimeException;

public class SMB2MessageConverter {

    private SMB2Packet getPacketInstance(SMB2PacketData packetData) {
        SMB2MessageCommandCode command = packetData.getHeader().getMessage();
        switch (command) {
            case SMB2_NEGOTIATE:
                return new SMB2NegotiateResponse();
            case SMB2_SESSION_SETUP:
                return new SMB2SessionSetup();
            case SMB2_TREE_CONNECT:
                return new SMB2TreeConnectResponse();
            case SMB2_TREE_DISCONNECT:
                return new SMB2TreeDisconnect();
            case SMB2_LOGOFF:
                return new SMB2Logoff();
            case SMB2_CREATE:
                return new SMB2CreateResponse();
            case SMB2_CHANGE_NOTIFY:
                return new SMB2ChangeNotifyResponse();
            case SMB2_QUERY_DIRECTORY:
                return new SMB2QueryDirectoryResponse();
            case SMB2_ECHO:
                return new SMB2Echo();
            case SMB2_READ:
                return new SMB2ReadResponse();
            case SMB2_CLOSE:
                return new SMB2Close();
            case SMB2_FLUSH:
                return new SMB2Flush();
            case SMB2_WRITE:
                return new SMB2WriteResponse();
            case SMB2_IOCTL:
                return new SMB2IoctlResponse();
            case SMB2_QUERY_INFO:
                return new SMB2QueryInfoResponse();
            case SMB2_SET_INFO:
                return new SMB2SetInfoResponse();
            case SMB2_LOCK:
            case SMB2_CANCEL:
            case SMB2_OPLOCK_BREAK:
            default:
                throw new SMBRuntimeException("Unknown SMB2 Message Command type: " + command);

        }
    }

    public SMB2Packet readPacket(SMBPacket requestPacket, SMB2PacketData packetData) throws Buffer.BufferException {
        SMB2Packet responsePacket = getPacketInstance(packetData);
        if (isSuccess(requestPacket, packetData)) {
            responsePacket.read(packetData);
        } else {
            responsePacket.readError(packetData);
        }
        return responsePacket;
    }

    /**
     * [MS-SMB2].pdf 3.3.4.4
     */
    private boolean isSuccess(SMBPacket requestPacket, SMB2PacketData packetData) {
        if (packetData.isSuccess()) {
            return true;
        }
        SMB2MessageCommandCode message = packetData.getHeader().getMessage();
        long statusCode = packetData.getHeader().getStatusCode();
        switch (message) {
            case SMB2_SESSION_SETUP:
                return statusCode == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue();
            case SMB2_CHANGE_NOTIFY:
                return statusCode == NtStatus.STATUS_NOTIFY_ENUM_DIR.getValue();
            case SMB2_READ:
            case SMB2_QUERY_INFO:
                return statusCode == NtStatus.STATUS_BUFFER_OVERFLOW.getValue();
            case SMB2_IOCTL:
//                SMB2IoctlRequest r = (SMB2IoctlRequest) requestPacket;
//                long controlCode = r.getControlCode();
                return statusCode == NtStatus.STATUS_BUFFER_OVERFLOW.getValue() || statusCode == NtStatus.STATUS_INVALID_PARAMETER.getValue();
            default:
                return false;
        }
    }
}
