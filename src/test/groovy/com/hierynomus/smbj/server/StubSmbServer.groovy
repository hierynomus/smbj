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
package com.hierynomus.smbj.server

import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import com.hierynomus.smb.SMBBuffer
import org.apache.commons.io.IOUtils
import org.slf4j.LoggerFactory

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

import static java.util.concurrent.TimeUnit.MILLISECONDS
import static org.junit.jupiter.api.Assertions.fail

class StubSmbServer {
  private static final def logger = LoggerFactory.getLogger(StubSmbServer.class)
  private int port = 0
  private ServerSocket socket

  private Deque<Response> stubbedResponses = new ArrayDeque<>()
  private Thread thread
  private AtomicBoolean stop = new AtomicBoolean(false)
  private AtomicReference<RuntimeException> serverException = new AtomicReference<>()

  StubSmbServer() {
    this(0)
  }

  StubSmbServer(int port) {
    this.port = port
  }

  void start() {
    try {
      socket = new ServerSocket(port)
      thread = new Thread(new Runnable() {
        @Override
        void run() {
          logger.info("Stub server started")
          runServer()
        }
      }, "Stub-Server-" + socket.getLocalPort())
      thread.start()
    } catch (IOException e) {
      throw new RuntimeException(e)
    }
  }

  private void runServer() {
    Socket accept = socket.accept()
    try {
      InputStream inputStream = accept.getInputStream()
      OutputStream outputStream = accept.getOutputStream()
      while (!stop.get() && !socket.isClosed()) {// && inputStream.available() > 4) {
        int packetLength = readTcpHeader(inputStream)
        if (packetLength < 0) {
          break
        }
        logger.debug("Read header of {} bytes", packetLength)
        // Read the SMB packet
        IOUtils.read(inputStream, new byte[packetLength])
        logger.debug("Read packet")
        if (!stubbedResponses.peekLast()) {
          fail("The response list is empty!")
        }

        Response response = stubbedResponses.removeFirst()
        response.write(outputStream)
        outputStream.flush()
      }

    } catch (IOException | Buffer.BufferException e) {
      serverException.set(new RuntimeException(e))
      throw serverException.get()
    } catch (InterruptedException e) {
      // no-op - quit loop
    } finally {
      accept.close()
    }
  }

  private static int readTcpHeader(InputStream inputStream) throws IOException, Buffer.BufferException, InterruptedException {

    while (inputStream.available() == 0) {
      MILLISECONDS.sleep(5)
    }

    byte[] b = new byte[4]
    int read = IOUtils.read(inputStream, b)
    if (read < b.length) {
      return -1
    }
    Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(b, Endian.BE)
    plainBuffer.readByte() // Ignore first byte
    return plainBuffer.readUInt24()
  }

  void shutdown() {
    stop.set(true)
    thread.interrupt()
    try {
      thread.join()
    } catch (InterruptedException e) {
      // Ignore
    }
    RuntimeException runtimeException = serverException.get()
    if (runtimeException != null) {
      throw runtimeException
    }
  }

  int getPort() {
    return socket.getLocalPort()
  }

  void registerResponse(File file) {
    stubbedResponses.add(new FileResponse(file))
  }

  void registerResponse(String resource) {
    stubbedResponses.add(new ResourceResponse(resource))
  }

  void registerResponse(byte[] bytes) {
    stubbedResponses.add(new ByteResponse(bytes))
  }

  void registerResponse(SMB2Packet packet) {
    stubbedResponses.add(new Smb2PacketResponse(packet))
  }

  private interface Response {
    void write(OutputStream outputStream)
  }

  private static class FileResponse implements Response {
    private File file

    private FileResponse(File file) {
      this.file = file
    }

    @Override
    void write(OutputStream outputStream) {
      new FileInputStream(file).withCloseable { fis ->
        IOUtils.copy(fis, outputStream)
      }
    }
  }

  private static class ResourceResponse implements Response {

    private String resource

    private ResourceResponse(String resource) {
      this.resource = resource
    }

    @Override
    void write(OutputStream outputStream) {
      Thread.currentThread().getContextClassLoader().getResourceAsStream(resource).withCloseable { is ->
        IOUtils.copy(is, outputStream)
      }
    }
  }

  private static class ByteResponse implements Response {
    private byte[] bytes

    private ByteResponse(byte[] bytes) {
      this.bytes = bytes
    }

    @Override
    void write(OutputStream outputStream) {
      outputStream.write(bytes)
    }
  }

  private static class Smb2PacketResponse implements Response {

    private SMB2Packet packet

    Smb2PacketResponse(SMB2Packet packet) {
      this.packet = packet
    }

    @Override
    void write(OutputStream outputStream) {
      def buffer = new SMBBuffer()
      packet.write(buffer)
      outputStream.write(new Buffer.PlainBuffer(Endian.BE).putByte((byte) 0).putUInt24(buffer.available()).array())
      outputStream.write(buffer.getCompactData())
    }
  }
}
