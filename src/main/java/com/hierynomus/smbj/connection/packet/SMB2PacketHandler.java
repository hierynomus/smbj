package com.hierynomus.smbj.connection.packet;


import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.PacketData;

public class SMB2PacketHandler implements IncomingPacketHandler {
    @Override
    public boolean canHandle(PacketData<?> packetData) {
        return packetData instanceof SMB2PacketData;
    }

    @Override
    public void handle(PacketData<?> packetData) {

    }
}
