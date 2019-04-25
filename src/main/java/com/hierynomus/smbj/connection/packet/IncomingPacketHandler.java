package com.hierynomus.smbj.connection.packet;

import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.transport.TransportException;

public interface IncomingPacketHandler {

    boolean canHandle(PacketData<?> packetData);

    void handle(PacketData<?> packetData) throws TransportException;
}
