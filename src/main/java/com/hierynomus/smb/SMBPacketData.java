package com.hierynomus.smb;

import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;

/**
 * The SMB Packet Data represents a partially deserialized SMB packet.
 * Only the header part is deserialized after which we can determine which packet
 * needs to be constructed.
 *
 * @param <H> The SMBHeader type
 */
public abstract class SMBPacketData<H extends SMBHeader> implements PacketData<SMBBuffer> {
    private H header;
    protected SMBBuffer dataBuffer;

    public SMBPacketData(H header, byte[] data) throws Buffer.BufferException {
        this.header = header;
        this.dataBuffer = new SMBBuffer(data);
        readHeader();
    }

    protected void readHeader() throws Buffer.BufferException {
        this.header.readFrom(dataBuffer);
    }

    public H getHeader() {
        return header;
    }

    @Override
    public SMBBuffer getDataBuffer() {
        return dataBuffer;
    }
}
