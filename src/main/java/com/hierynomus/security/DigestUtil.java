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
package com.hierynomus.security;

import com.hierynomus.mssmb.SMB1Packet;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;

public class DigestUtil {
    public static byte[] concatenatePreviousUpdateDigest(MessageDigest messageDigest, byte[] previousBytes, byte[] updateBytes) {
        messageDigest.update(previousBytes);
        messageDigest.update(updateBytes);
        return messageDigest.digest();
    }

    public static byte[] getRequestPacketBytes(SMBPacket request) {
        if (request == null) {
            throw new IllegalStateException("passing null to getRequestPacketBytes method");
        }

        SMBBuffer buffer = new SMBBuffer();

        if (request instanceof SMB2Packet) {
            SMB2Packet smb2Packet = ((SMB2Packet) request);
            smb2Packet.write(buffer);
        } else if(request instanceof SMB1Packet) {
            // also handle for the SMB1ComNegotiateRequest packet case
            SMB1Packet smb1Packet = (SMB1Packet)request;
            smb1Packet.write(buffer);
        } else {
            throw new IllegalStateException("passing unknown request packet to getRequestPacketBytes method");
        }

        return buffer.getCompactData();
    }

    public static byte[] getResponsePacketBytes(SMB2Packet response) {
        if (response == null) {
            throw new IllegalStateException("passing null to getResponsePacketBytes method");
        }

        // extract the context bytes
        SMBBuffer responseBuffer = response.getBuffer();
        // record the original read position
        int originalPos = responseBuffer.rpos();
        // seek to 0 and get whole response bytes
        responseBuffer.rpos(0);
        byte[] responseBytes = responseBuffer.getCompactData();
        // seek back to original read position
        responseBuffer.rpos(originalPos);

        return responseBytes;
    }
}
