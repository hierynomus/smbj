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

import com.hierynomus.mssmb2.SMB2DeadLetterPacketData;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.OutstandingRequests;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        long messageId = packetData.getSequenceNumber();

        if (!outstandingRequests.isOutstanding(messageId) && !packetData.isOplockBreakNotification()) {
            logger.error("Received response with unknown sequence number << {} >>", messageId);
            next.handle(new SMB2DeadLetterPacketData(packetData.getHeader()));
        } else {
            next.handle(packetData);
        }

    }
}
