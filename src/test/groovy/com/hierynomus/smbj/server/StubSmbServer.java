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
package com.hierynomus.smbj.server;

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class StubSmbServer {

    private int port = 0;
    private ServerSocket socket;

    private List<Response> stubbedResponses = new ArrayList<>();
    private Thread thread;
    private AtomicBoolean stop = new AtomicBoolean(false);
    private AtomicReference<RuntimeException> serverException = new AtomicReference<>();

    public StubSmbServer() {
        this(0);
    }

    public StubSmbServer(int port) {
        this.port = port;
    }

    public void start() {
        try {
            socket = new ServerSocket(port);
            thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    runServer();
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runServer() {
        try (Socket accept = socket.accept()) {
            InputStream inputStream = accept.getInputStream();
            OutputStream outputStream = accept.getOutputStream();
            while (!stop.get()) {
                int packetLength = readTcpHeader(inputStream);
                // Read the SMB packet
                IOUtils.read(inputStream, new byte[packetLength]);
                if (stubbedResponses.size() > 0) {
                    Response response = stubbedResponses.remove(0);
                    byte[] b = IOUtils.toByteArray(response.getBytes());
                    outputStream.write(new Buffer.PlainBuffer(Endian.BE).putByte((byte) 0).putUInt24(b.length).array());
                    outputStream.write(b);
                    outputStream.flush();
                } else {
                    throw new NoSuchElementException("The response list is empty!");
                }
            }

        } catch (IOException | Buffer.BufferException e) {
            serverException.set(new RuntimeException(e));
            throw serverException.get();
        }
    }

    private int readTcpHeader(InputStream inputStream) throws IOException, Buffer.BufferException {
        byte[] b = new byte[4];
        IOUtils.read(inputStream, b);
        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(b, Endian.BE);
        plainBuffer.readByte(); // Ignore first byte
        return plainBuffer.readUInt24();
    }

    public void shutdown() {
        stop.set(true);
        try {
            thread.join();
        } catch (InterruptedException e) {
            // Ignore
        }
        RuntimeException runtimeException = serverException.get();
        if (runtimeException != null) {
            throw runtimeException;
        }
    }

    public int getPort() {
        return socket.getLocalPort();
    }

    public void registerResponse(File file) {
        stubbedResponses.add(new FileResponse(file));
    }

    public void registerResponse(String resource) {
        stubbedResponses.add(new ResourseResponse(resource));
    }

    public void registerResponse(byte[] bytes) {
        stubbedResponses.add(new ByteResponse(bytes));
    }

    private interface Response {
        InputStream getBytes();
    }

    private static class FileResponse implements Response {
        private File file;

        private FileResponse(File file) {
            this.file = file;
        }

        @Override
        public InputStream getBytes() {
            try {
                return new FileInputStream(file);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class ResourseResponse implements Response {

        private String resource;

        private ResourseResponse(String resource) {
            this.resource = resource;
        }

        @Override
        public InputStream getBytes() {
            return Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        }
    }

    private static class ByteResponse implements Response {
        private byte[] bytes;

        private ByteResponse(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public InputStream getBytes() {
            return new ByteArrayInputStream(bytes);
        }
    }
}
