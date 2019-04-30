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
package com.hierynomus.smbj.connection.packet;


import com.hierynomus.mssmb.SMB1NotSupportedException;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.transport.TransportException;

public abstract class SMB2PacketHandler extends AbstractIncomingPacketHandler {
    @Override
    public boolean canHandle(PacketData<?> packetData) {
        return packetData instanceof SMB2PacketData;
    }

    @Override
    protected void doHandle(PacketData<?> packetData) throws TransportException {
        doSMB2Handle((SMB2PacketData) packetData);
    }

    protected abstract void doSMB2Handle(SMB2PacketData packetData) throws TransportException;

}
