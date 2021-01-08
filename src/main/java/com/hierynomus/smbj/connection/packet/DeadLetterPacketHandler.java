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

import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBPacketData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DeadLetterPacketHandler extends AbstractIncomingPacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(DeadLetterPacketHandler.class);
    @Override
    protected boolean canHandle(SMBPacketData<?> packetData) {
        return true;
    }

    @Override
    protected void doHandle(SMBPacketData<?> packetData) throws TransportException {
        logger.warn("Packet << {} >> ended up in dead letters", packetData);
    }
}
