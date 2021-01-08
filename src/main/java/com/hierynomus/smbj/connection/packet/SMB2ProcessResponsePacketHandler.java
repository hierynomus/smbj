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

import com.hierynomus.mssmb2.SMB2MessageConverter;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.OutstandingRequests;
import com.hierynomus.smbj.connection.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [MS-SMB2] 3.2.5.1.7 Handling Incorrectly Formatted Responses AND 3.2.5.1.8 Processing the Response
 * <p>
 * If the client receives a response that does not conform to the structures specified in 2,
 * the client MUST discard the response and fail the corresponding application request with an error
 * indicating that an invalid network response was received. The client MAY<154> also disconnect the connection.
 * <p>
 * The client MUST process the response based on the Command field of the SMB2 header of the response.
 * When the processing is completed, the corresponding request MUST be removed from Connection.OutstandingRequests.
 * The corresponding request MUST also be removed from Open.OutstandingRequests, if it exists.
 * <p>
 * If the command that is received is not a valid command, or if the server returned a command that did not match
 * the command of the request, the client SHOULD<155> fail the application request with an implementation-specific
 * error that indicates an invalid network response was received.
 */
public class SMB2ProcessResponsePacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2ProcessResponsePacketHandler.class);
    private final SMB2MessageConverter smb2Converter;
    private final OutstandingRequests outstandingRequests;

    public SMB2ProcessResponsePacketHandler(SMB2MessageConverter smb2Converter, OutstandingRequests outstandingRequests) {
        this.smb2Converter = smb2Converter;
        this.outstandingRequests = outstandingRequests;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        Request request = outstandingRequests.getRequestByMessageId(packetData.getHeader().getMessageId());

        SMB2Packet packet = null;
        try {
            packet = smb2Converter.readPacket(request.getPacket(), packetData);
        } catch (Buffer.BufferException e) {
            logger.error("Failed to deserialize SMB2 Packet Data of {}", packetData);

            throw new TransportException("Unable to deserialize SMB2 Packet Data.", e);
        }

        outstandingRequests.receivedResponseFor(packet.getHeader().getMessageId()).getPromise().deliver(packet);
    }
}
