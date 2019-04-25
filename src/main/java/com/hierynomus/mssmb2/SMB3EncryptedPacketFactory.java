package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.PacketFactory;

import java.io.IOException;

public class SMB3EncryptedPacketFactory implements PacketFactory<SMB3EncryptedPacketData> {
    @Override
    public SMB3EncryptedPacketData read(byte[] data) throws Buffer.BufferException, IOException {
        return new SMB3EncryptedPacketData(data);
    }

    @Override
    public boolean canHandle(byte[] data) {
        return data[0] == (byte) 0xFD && data[1] == 'S' && data[2] == 'M' && data[3] == 'B';
    }
}
