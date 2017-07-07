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
package com.hierynomus.smbj.connection;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2MessageConverter;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.transport.PacketHandlers;
import com.hierynomus.smbj.transport.PacketReceiver;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.smbj.transport.tcp.AsyncDirectTcpTransport;

import java.io.IOException;
import java.nio.channels.AsynchronousChannelGroup;
import java.util.concurrent.ExecutorService;

public class AsyncDirectTcpTransportFactory implements TransportLayerFactory<SMB2Packet> {
    private static final AsynchronousChannelGroup DEFAULT_CHANNEL_GROUP = null;  // use system default
    private static final SMB2MessageConverter converter = new SMB2MessageConverter();
    private final AsynchronousChannelGroup group;

    @Override
    public TransportLayer<SMB2Packet> createTransportLayer(PacketReceiver<SMB2Packet> receiver, SmbConfig config) {
        PacketHandlers<SMB2Packet> handlers = new PacketHandlers<>(converter, receiver, converter);
        try {
            return new AsyncDirectTcpTransport<SMB2Packet>(config.getSoTimeout(), handlers, group);
        } catch (IOException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public AsyncDirectTcpTransportFactory() {
        this((AsynchronousChannelGroup) DEFAULT_CHANNEL_GROUP);
    }

    public AsyncDirectTcpTransportFactory(ExecutorService executor) {
        this(createGroup(executor));
    }

    public AsyncDirectTcpTransportFactory(AsynchronousChannelGroup group) {
        this.group = group;
    }

    private static AsynchronousChannelGroup createGroup(ExecutorService executor) {
        try {
            return AsynchronousChannelGroup.withThreadPool(executor);
        } catch (IOException e) {
            throw new RuntimeException(e); // unable to create new threads?
        }
    }
}
