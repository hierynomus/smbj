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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2Packet;
import com.hierynomus.smbj.smb2.messages.SMB2ResponseMessageFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.ReentrantLock;

public class PacketReader {

    private InputStream in;
    private SequenceWindow sequenceWindow;

    private ReentrantLock lock = new ReentrantLock();

    public PacketReader(InputStream in, SequenceWindow sequenceWindow) {
        this.in = in;
        this.sequenceWindow = sequenceWindow;
    }

    public SMB2Packet readPacket() throws TransportException {
        lock.lock();
        try {
            SMB2Packet smb2Packet = _readTcpPacket();
            // Grant the credits from the response.
            sequenceWindow.creditsGranted(smb2Packet.getHeader().getCreditResponse());
            return smb2Packet;
        } catch (IOException | Buffer.BufferException e) {
            throw new TransportException(e);
        } finally {
            lock.unlock();
        }
    }

    private SMB2Packet _readTcpPacket() throws IOException, Buffer.BufferException {
        byte[] tcpHeader = new byte[4];
        in.read(tcpHeader);
        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(tcpHeader, Endian.BE);
        plainBuffer.readByte();
        int packetLength = plainBuffer.readUInt24();
        return _readSMB2Packet(packetLength);
    }

    private SMB2Packet _readSMB2Packet(int packetLength) throws IOException, Buffer.BufferException {
        byte[] smb2Packet = new byte[packetLength];
        in.read(smb2Packet);
        SMBBuffer buffer = new SMBBuffer(smb2Packet);
        return SMB2ResponseMessageFactory.read(buffer);
    }
}
