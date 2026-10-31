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

import com.hierynomus.mssmb2.DeadLetterPacketData;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.connection.OutstandingRequests;
import com.hierynomus.smbj.connection.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_SESSION_SETUP;

/**
 * [MS-SMB2] 3.2.5.1.2 Finding the Application Request for This Response
 * <p>
 * The client MUST locate the request for which this response was sent in reply by locating the request in
 * Connection.OutstandingRequests using the MessageId field of the SMB2 header. If the request is not found,
 * the response MUST be discarded as invalid.
 * <p>
 * If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request, and the client MUST NOT attempt
 * to locate the request, but instead process it as follows:
 * <p>
 * If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
 * Otherwise, the response MUST be discarded as invalid.
 */
public class SMB2IsOutstandingPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2IsOutstandingPacketHandler.class);
    private OutstandingRequests outstandingRequests;

    public SMB2IsOutstandingPacketHandler(OutstandingRequests outstandingRequests) {
        this.outstandingRequests = outstandingRequests;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        if (!isValid(packetData)) {
            next.handle(new DeadLetterPacketData(packetData.getHeader()));
        } else {
            next.handle(packetData);
        }
    }

    boolean isValid(SMB2PacketData packetData) throws TransportException {
        if (packetData.isOplockBreakNotification()) {
            return true;
        }
        long messageId = packetData.getSequenceNumber();
        Request request = outstandingRequests.getRequestByMessageId(messageId);
        if (request == null) {
            logger.warn("Received response with unknown sequence number << {} >>", messageId);
            return false;
        }
        if (packetData.getHeader().getStatusCode() == NtStatus.STATUS_PENDING.getValue()
            && (!packetData.isIntermediateAsyncResponse() || !hasEmptyErrorBody(packetData))) {
            logger.warn("Received invalid interim response {}, discarding", packetData);
            return false;
        }
        if (request.isEncrypted() && !packetData.isIntermediateAsyncResponse()) {
            if (!packetData.isDecrypted()) {
                throw new TransportException("Unencrypted final response to encrypted request " + messageId);
            }
            if (packetData.getHeader().getSessionId() != request.getSessionId()) {
                throw new TransportException("Session ID of encrypted final response differs from request " + messageId);
            }
        }
        if (packetData.getHeader().getMessage() != request.getCommand()) {
            logger.warn("Received response {} with command differing from request {}", packetData, request.getCommand());
            return false;
        }
        // The first SESSION_SETUP response assigns the session ID for subsequent exchanges.
        boolean initialSessionSetup = request.getCommand() == SMB2_SESSION_SETUP && request.getSessionId() == 0;
        if (!initialSessionSetup && packetData.getHeader().getSessionId() != request.getSessionId()) {
            logger.warn("Received response {} with session ID differing from request session << {} >>", packetData, request.getSessionId());
            return false;
        }
        return true;
    }

    private boolean hasEmptyErrorBody(SMB2PacketData packetData) {
        SMBBuffer buffer = packetData.getDataBuffer();
        int start = packetData.getHeader().getHeaderStartPosition() + SMB2PacketHeader.STRUCTURE_SIZE;
        int end = packetData.getHeader().getMessageEndPosition();
        if (start < 0 || end > buffer.wpos() || end - start < 8 || end - start > 16) {
            return false;
        }
        int rpos = buffer.rpos();
        try {
            buffer.rpos(start);
            if (buffer.readUInt16() != 9 || buffer.readByte() != 0) {
                return false;
            }
            buffer.skip(1); // Reserved
            // ErrorData and padding are unauthenticated and have no meaning when ByteCount is zero.
            return buffer.readUInt32() == 0;
        } catch (Buffer.BufferException | IllegalArgumentException | IndexOutOfBoundsException e) {
            return false;
        } finally {
            buffer.rpos(rpos);
        }
    }
}
