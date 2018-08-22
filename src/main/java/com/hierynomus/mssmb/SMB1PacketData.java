package com.hierynomus.mssmb;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBPacketData;

public class SMB1PacketData extends SMBPacketData<SMB1Header> {
    public SMB1PacketData(byte[] data) throws Buffer.BufferException {
        super(new SMB1Header(), data);
    }
}
