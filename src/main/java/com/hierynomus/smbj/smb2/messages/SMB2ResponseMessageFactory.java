/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.transport.TransportException;

public class SMB2ResponseMessageFactory {

    public static SMB2Packet read(SMBBuffer buffer) throws Buffer.BufferException, TransportException {
        // Check we see a valid header start
        Check.ensureEquals(buffer.readRawBytes(4), new byte[] {(byte) 0xFE, 'S', 'M', 'B'}, "Could not find SMB2 Packet header");
        // Skip until Command
        buffer.skip(8);
        int command = buffer.readUInt16();
        // Reset read position so that the message works.
        buffer.rpos(0);
        switch (command) {
            case 0x0: // SMB2_NEGOTIATE
                return new SMB2NegotiateResponse().read(buffer);
            default:
                throw new TransportException("Unknown SMB2 Message Command type: " + command);

        }
    }
}
