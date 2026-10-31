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
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.DeadLetterPacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.connection.OutstandingRequests;
import com.hierynomus.smbj.connection.SessionTable;
import com.hierynomus.smbj.connection.Signatory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private static final Logger logger = LoggerFactory.getLogger(SMB2CompoundedPacketHandler.class);
    private final SMB2IsOutstandingPacketHandler outstandingHandler;
    private final SMB2SignatureVerificationPacketHandler signatureHandler;

    /**
     * Creates a handler that only splits compounded frames, without validating their members.
     * @deprecated use {@link #SMB2CompoundedPacketHandler(OutstandingRequests, SessionTable, Signatory)}
     */
    @Deprecated
    public SMB2CompoundedPacketHandler() {
        this.outstandingHandler = null;
        this.signatureHandler = null;
    }

    /**
     * Creates a handler that validates all responses in a frame before forwarding any of them.
     * @param outstandingRequests the requests awaiting responses
     * @param sessionTable the established sessions
     * @param signatory the signature verifier
     */
    public SMB2CompoundedPacketHandler(OutstandingRequests outstandingRequests, SessionTable sessionTable, Signatory signatory) {
        this.outstandingHandler = new SMB2IsOutstandingPacketHandler(outstandingRequests);
        this.signatureHandler = new SMB2SignatureVerificationPacketHandler(sessionTable, signatory, outstandingRequests);
    }

    @Override
    public boolean canHandle(SMBPacketData<?> packetData) {
        return super.canHandle(packetData) && (outstandingHandler != null || ((SMB2PacketData) packetData).isCompounded());
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        List<SMB2PacketData> members = new ArrayList<>();
        SMB2PacketData member = packetData;
        boolean compounded = packetData.isCompounded();
        try {
            do {
                SMB2PacketHeader header = member.getHeader();
                if (compounded && !hasValidBounds(member)) {
                    discard(packetData);
                    return;
                }
                members.add(member);
                if (!member.isCompounded()) {
                    break;
                }
                // Splitting must not depend on a downstream handler consuming the body.
                member.getDataBuffer().rpos(header.getMessageEndPosition());
                member = member.next();
            } while (member != null);
        } catch (Buffer.BufferException | IllegalArgumentException | IndexOutOfBoundsException e) {
            logger.warn("Malformed compounded response {}, dropping frame", packetData, e);
            discard(packetData);
            return;
        }

        if (outstandingHandler != null) {
            Set<Long> completedRequests = new HashSet<>();
            for (SMB2PacketData response : members) {
                if (packetData.isDecrypted() && response.getHeader().getSessionId() != packetData.getHeader().getSessionId()) {
                    logger.warn("Mismatched session ID in decrypted response frame {}", packetData);
                    discard(packetData);
                    return;
                }
                if (!outstandingHandler.isValid(response) || !signatureHandler.isValid(response)) {
                    discard(packetData);
                    return;
                }
                if (!response.isOplockBreakNotification()) {
                    long messageId = response.getSequenceNumber();
                    if (completedRequests.contains(messageId)) {
                        logger.warn("Repeated response for message << {} >> in frame {}", messageId, packetData);
                        discard(packetData);
                        return;
                    }
                    if (!response.isIntermediateAsyncResponse()) {
                        completedRequests.add(messageId);
                    }
                }
            }
        }
        for (SMB2PacketData response : members) {
            if (compounded) {
                response.getDataBuffer().rpos(response.getHeader().getHeaderStartPosition() + SMB2PacketHeader.STRUCTURE_SIZE);
            }
            next.handle(response);
        }
    }

    private boolean hasValidBounds(SMB2PacketData member) {
        SMB2PacketHeader header = member.getHeader();
        int start = header.getHeaderStartPosition();
        int length = member.getDataBuffer().wpos();
        int offset = header.getNextCommandOffset();
        if (start < 0 || start > length - SMB2PacketHeader.STRUCTURE_SIZE) {
            return false;
        }
        if (offset == 0) {
            return header.getMessageEndPosition() == length;
        }
        return offset >= SMB2PacketHeader.STRUCTURE_SIZE && (offset & 7) == 0
            && offset <= length - start - SMB2PacketHeader.STRUCTURE_SIZE
            && header.getMessageEndPosition() == start + offset;
    }

    private void discard(SMB2PacketData packetData) throws TransportException {
        logger.warn("Discarding response frame {} before processing any members", packetData);
        next.handle(new DeadLetterPacketData(packetData.getHeader()));
    }
}
