package com.hierynomus.smbj.transport.tcp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketBufferReader {
    private static final int NO_PACKET_LENGTH = -1;
    private static final int HEADER_SIZE = 4;
    private static final int READ_BUFFER_CAPACITY = 9000; // Size of a Jumbo frame

    private final ByteBuffer readBuffer;

    private int currentPacketLength = NO_PACKET_LENGTH;

    public PacketBufferReader() {
        this.readBuffer = ByteBuffer.allocate(READ_BUFFER_CAPACITY);
        this.readBuffer.order(ByteOrder.BIG_ENDIAN);
    }
    
    public byte[] readNext() {
        readBuffer.flip(); // prepare to process received data
        byte[] result;
        if (isAwaitingHeader()) {
            result = readPacketHeaderAndBody();
        } else {
            result = readPacketBody();
        }
        readBuffer.compact(); // prepare to receive more data
        return result;
    }

    public ByteBuffer getBuffer() {
        return readBuffer;
    }

    private boolean isAwaitingHeader() {
        return currentPacketLength == NO_PACKET_LENGTH;
    }

    private byte[] readPacketHeaderAndBody() {
        if (!ensureBytesAvailable(HEADER_SIZE)) {
            return null; // can't read header yet
        }
        this.currentPacketLength = readBuffer.getInt() & 0xffffff;
        return readPacketBody();
    }

    private byte[] readPacketBody() {
        if (!ensureBytesAvailable(this.currentPacketLength)) {
            return null; // can't read body yet
        }
        byte[] buf = new byte[this.currentPacketLength];
        readBuffer.get(buf);
        this.currentPacketLength = NO_PACKET_LENGTH; // prepare to read next packet
        return buf;
    }

    private boolean ensureBytesAvailable(int bytesNeeded) {
        return readBuffer.remaining() >= bytesNeeded;
    }

}
