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
import com.hierynomus.smbj.connection.SequenceWindow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [MS-SMB2] 3.2.5.1.4 Granting Message Credits
 *
 * If CreditResponse is greater than 0, the client MUST insert the newly granted credits into the
 * Connection.SequenceWindow. For each credit that is granted, the client MUST insert the next highest value into the
 * sequence window, as specified in section 3.2.4.1.6. The client MUST then signal any requests that were waiting for
 * available message identifiers to continue processing.
 */
public class SMB2CreditGrantingPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(SMB2CreditGrantingPacketHandler.class);
    private SequenceWindow sequenceWindow;

    public SMB2CreditGrantingPacketHandler(SequenceWindow sequenceWindow) {
        this.sequenceWindow = sequenceWindow;
    }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        sequenceWindow.creditsGranted(packetData.getHeader().getCreditResponse());
        logger.debug("Server granted us {} credits for {}, now available: {} credits", packetData.getHeader().getCreditResponse(), packetData, sequenceWindow.available());
        next.handle(packetData);
    }
}
