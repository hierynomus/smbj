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
package com.hierynomus.smbj.transport;

import com.hierynomus.smbj.common.SMBBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * A transport layer to do SMB2 over Direct TCP/IP.
 */
public class DirectTcpTransport extends BaseTransport implements TransportLayer {
    private static final Logger logger = LoggerFactory.getLogger(DirectTcpTransport.class);

    @Override
    protected void doWrite(SMBBuffer packetData) throws IOException {
        // Wrap in the Direct TCP packet header
        DirectTcpPacket directTcpPacket = new DirectTcpPacket(packetData);
        out.write(directTcpPacket.array(), directTcpPacket.rpos(), directTcpPacket.available());
    }

    @Override
    public int getDefaultPort() {
        return 445;
    }
}
