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
package com.hierynomus.smbj.transport.tcp.direct;

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.transport.PacketFactory;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.PacketReceiver;
import com.hierynomus.smbj.transport.TransportException;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class DirectTcpPacketReader<P extends Packet<P, ?>> extends PacketReader<P> {

    private final PacketFactory<P> packetFactory;

    public DirectTcpPacketReader(String host, InputStream in, PacketFactory<P> packetFactory, PacketReceiver<P> handler) {
        super(host, in, handler);
        this.packetFactory = packetFactory;
    }

    private P _readSMB2Packet(int packetLength) throws IOException, Buffer.BufferException {
        byte[] buf = new byte[packetLength];
        int count = 0;
        int read = 0;
        while (count < packetLength && ((read = in.read(buf, count, packetLength - count)) != -1)) {
            count += read;
        }
        if (read == -1) {
            throw new TransportException(new EOFException("EOF while reading packet"));
        }

        return packetFactory.read(buf);
    }

    @Override
    protected P doRead() throws TransportException {
        try {
            int smb2PacketLength = _readTcpHeader();
            return _readSMB2Packet(smb2PacketLength);
        } catch (TransportException e) {
            throw e;
        } catch (IOException | Buffer.BufferException e) {
            throw new TransportException(e);
        }
    }

    private int _readTcpHeader() throws IOException, Buffer.BufferException {
        byte[] tcpHeader = new byte[4];
        readFully(tcpHeader);
        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(tcpHeader, Endian.BE);
        plainBuffer.readByte();
        int packetLength = plainBuffer.readUInt24();
        return packetLength;
    }

    private void readFully(byte[] buffer) throws IOException {
        int toRead = buffer.length;
        int offset = 0;
        while (toRead > 0) {
            int bytesRead = in.read(buffer, offset, toRead);
            if (bytesRead == -1) {
                throw new TransportException(new EOFException("EOF while reading packet"));
            }
            toRead -= bytesRead;
            offset += bytesRead;
        }
    }
}
