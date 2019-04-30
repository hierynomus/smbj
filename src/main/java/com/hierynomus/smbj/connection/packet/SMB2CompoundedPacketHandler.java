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
package com.hierynomus.smbj.connection.packet;

import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;

/**
 * [MS-SMB2] 3.2.5.1.9 Handling Compounded Responses
 * <p>
 * A client detects that a server sent a compounded response (multiple responses chained together into a single
 * network send) by checking if the NextCommand in the SMB2 header of the response is not equal to 0. The client
 * MUST handle compounded responses by separating them into individual responses, regardless of any compounding
 * used when sending the requests.
 * <p>
 * For a series of responses compounded together, each response MUST be processed in order as an individual message
 * with a size, in bytes, as determined by the NextCommand field in the SMB2 header.
 * <p>
 * The final response in the compounded response chain will have NextCommand equal to 0, and it MUST be processed
 * as an individual message of a size equal to the number of bytes remaining in this receive.
 */
public class SMB2CompoundedPacketHandler extends SMB2PacketHandler {
    @Override
    public boolean canHandle(PacketData<?> packetData) {
        return super.canHandle(packetData) && ((SMB2PacketData) packetData).isCompounded();
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        do {
            next.handle(packetData);
            try {
                packetData = packetData.next();
            } catch (Buffer.BufferException e) {
                throw new TransportException("Missing compounded message data", e);
            }
        } while (packetData != null);
    }
}
