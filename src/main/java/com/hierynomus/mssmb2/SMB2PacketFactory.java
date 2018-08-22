package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;

public class SMB2PacketFactory implements PacketFactory<SMB2PacketData> {

    @Override
    public SMB2PacketData read(byte[] data) throws Buffer.BufferException {
        return new SMB2PacketData(data);
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data[0] == (byte) 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }
}
