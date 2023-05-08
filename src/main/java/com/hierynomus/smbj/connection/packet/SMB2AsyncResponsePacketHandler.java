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
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.OutstandingRequests;
import com.hierynomus.smbj.connection.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 3.2.5.1.5 Handling Asynchronous Responses
 *
 * If SMB2_FLAGS_ASYNC_COMMAND is set in the Flags field of the SMB2 header of the response and the Status field in the
 * SMB2 header is STATUS_PENDING, the client MUST mark the request in Connection.OutstandingRequests as being handled
 * asynchronously by storing the AsyncId of the response in Request.AsyncId. The client SHOULD&lt;153&gt; extend the
 * Request Expiration Timer, as specified in section 3.2.6.1. Processing of this response is now complete.
 *
 * If SMB2_FLAGS_ASYNC_COMMAND is set in the Flags field of the SMB2 header and Status is not STATUS_PENDING,
 * this is a final response to a request which was processed by the server asynchronously, and processing MUST
 * continue as specified below.
 */
public class SMB2AsyncResponsePacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2AsyncResponsePacketHandler.class);
    private OutstandingRequests outstandingRequests;

    public SMB2AsyncResponsePacketHandler(OutstandingRequests outstandingRequests) {
        this.outstandingRequests = outstandingRequests;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        Request request = outstandingRequests.getRequestByMessageId(packetData.getHeader().getMessageId());
        logger.trace("Send/Recv of packet {} took << {} ms >>", packetData, System.currentTimeMillis() - request.getTimestamp().getTime());

        // [MS-SMB2] 3.2.5.1.5 Handling Asynchronous Responses
        if (packetData.isIntermediateAsyncResponse()) {
            logger.debug("Received ASYNC packet {} with AsyncId << {} >>", packetData, packetData.getHeader().getAsyncId());
            request.setAsyncId(packetData.getHeader().getAsyncId());
            // TODO expiration timer
            return;
        }

        next.handle(packetData);
    }
}
