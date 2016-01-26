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

import com.hierynomus.smbj.Config;
import com.hierynomus.smbj.common.DirectTcpPacket;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.messages.SMB2NegotiateRequest;
import com.hierynomus.smbj.smb2.messages.SMB2NegotiateResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;

public class TransportLayer {
    private static final Logger logger = LoggerFactory.getLogger(TransportLayer.class);
    private Config config;
    private ConnectionInfo connectionInfo;
    private InputStream in;
    private OutputStream out;

    private final ReentrantLock writeLock = new ReentrantLock();

    public TransportLayer(Config config) {
        this.config = config;
    }

    public void init(String host, int port, InputStream in, OutputStream out) throws TransportException {
        this.out = out;
        this.connectionInfo = new ConnectionInfo(host);
        this.in = in;
        negotiateDialect();
    }


    private void negotiateDialect() throws TransportException {
        SMB2Packet negotiatePacket = new SMB2NegotiateRequest(connectionInfo.getSequenceWindow().get(), config.getSupportedDialects(), connectionInfo.getClientGuid());
        write(negotiatePacket);
        SMB2Packet negotiateResponse = new PacketReader(in, connectionInfo.getSequenceWindow()).readPacket();
        if (!(negotiateResponse instanceof SMB2NegotiateResponse)) {
            throw new IllegalStateException("Expected a SMB2 NEGOTIATE Response, but got: " + negotiateResponse.getHeader().getMessageId());
        }
        SMB2NegotiateResponse resp = (SMB2NegotiateResponse) negotiateResponse;
        connectionInfo.negotiated(resp);
    }

    public long write(SMB2Packet packet) throws TransportException {
        writeLock.lock();
        try {
            try {
                packet.write();
                // Wrap in the Direct TCP packet header
                DirectTcpPacket directTcpPacket = new DirectTcpPacket(packet);
                out.write(directTcpPacket.array(), directTcpPacket.rpos(), directTcpPacket.available());
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
            return packet.getSequenceNumber();
        } finally {
            writeLock.unlock();
        }
    }

}
