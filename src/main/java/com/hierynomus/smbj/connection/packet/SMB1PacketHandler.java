package com.hierynomus.smbj.connection.packet;

import com.hierynomus.mssmb.SMB1NotSupportedException;
import com.hierynomus.mssmb.SMB1PacketData;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.transport.TransportException;

public class SMB1PacketHandler implements IncomingPacketHandler {
    @Override
    public boolean canHandle(PacketData<?> packetData) {
        return packetData instanceof SMB1PacketData;
    }

    @Override
    public void handle(PacketData<?> packetData) throws TransportException {
        throw new SMB1NotSupportedException();
    }
}
