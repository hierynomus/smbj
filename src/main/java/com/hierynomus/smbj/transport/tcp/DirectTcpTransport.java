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
package com.hierynomus.smbj.transport.tcp;

import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.transport.BaseTransport;
import com.hierynomus.smbj.transport.TransportLayer;

import java.io.IOException;

/**
 * A transport layer to do SMB2 over Direct TCP/IP.
 */
public class DirectTcpTransport extends BaseTransport implements TransportLayer {

    @Override
    protected void doWrite(SMBBuffer packetData) throws IOException {
        // Wrap in the Direct TCP packet header
        out.write(0);
        int available = packetData.available();
        out.write((byte) (available >> 16));
        out.write((byte) (available >> 8));
        out.write((byte) (available & 0xFF));
        out.write(packetData.array(), packetData.rpos(), packetData.available());
        out.flush();
    }

    @Override
    public int getDefaultPort() {
        return 445;
    }
}
