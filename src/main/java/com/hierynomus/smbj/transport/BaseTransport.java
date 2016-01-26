/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.transport;

import com.hierynomus.smbj.smb2.SMB2Packet;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BaseTransport implements TransportLayer {
    protected InputStream in;
    protected OutputStream out;

    private final ReentrantLock writeLock = new ReentrantLock();

    @Override
    public void init(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    @Override
    public long write(SMB2Packet packet) throws TransportException {
        writeLock.lock();
        try {
            try {
                packet.write();
                doWrite(packet);
                out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }
            return packet.getSequenceNumber();
        } finally {
            writeLock.unlock();
        }

    }

    protected abstract void doWrite(SMB2Packet packet) throws IOException;
}
