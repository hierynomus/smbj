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

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class StubSmbServer {

  private int port = 0
  private ServerSocket socket

  private List<Response> stubbedResponses = new ArrayList<>()
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
          runServer()
        }
      })
    } catch (IOException e) {
      throw new RuntimeException(e)
    }
  }

  private void runServer() {
    Socket accept = socket.accept()
    try {
      InputStream inputStream = accept.getInputStream()
      OutputStream outputStream = accept.getOutputStream()
      while (!stop.get()) {
        int packetLength = readTcpHeader(inputStream)
        // Read the SMB packet
        IOUtils.read(inputStream, new byte[packetLength])
        if (stubbedResponses.size() > 0) {
          Response response = stubbedResponses.remove(0)
          byte[] b = IOUtils.toByteArray(response.getBytes())
          outputStream.write(new Buffer.PlainBuffer(Endian.BE).putByte((byte) 0).putUInt24(b.length).array())
          outputStream.write(b)
          outputStream.flush()
        } else {
          throw new NoSuchElementException("The response list is empty!")
        }
      }

    } catch (IOException | Buffer.BufferException e) {
      serverException.set(new RuntimeException(e))
      throw serverException.get()
    } finally {
      accept.close()
    }
  }

  private static int readTcpHeader(InputStream inputStream) throws IOException, Buffer.BufferException {
    byte[] b = new byte[4]
    IOUtils.read(inputStream, b)
    Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(b, Endian.BE)
    plainBuffer.readByte() // Ignore first byte
    return plainBuffer.readUInt24()
  }

  void shutdown() {
    stop.set(true)
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
    InputStream getBytes()
  }

  private static class FileResponse implements Response {
    private File file

    private FileResponse(File file) {
      this.file = file
    }

    @Override
    InputStream getBytes() {
      try {
        return new FileInputStream(file)
      } catch (FileNotFoundException e) {
        throw new RuntimeException(e)
      }
    }
  }

  private static class ResourceResponse implements Response {

    private String resource

    private ResourseResponse(String resource) {
      this.resource = resource
    }

    @Override
    InputStream getBytes() {
      return Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)
    }
  }

  private static class ByteResponse implements Response {
    private byte[] bytes

    private ByteResponse(byte[] bytes) {
      this.bytes = bytes
    }

    @Override
    InputStream getBytes() {
      return new ByteArrayInputStream(bytes)
    }
  }

  private static class Smb2PacketResponse implements Response {

    private SMB2Packet packet

    Smb2PacketResponse(SMB2Packet packet) {
      this.packet = packet
    }

    @Override
    InputStream getBytes() {
      SMBBuffer buffer = new SMBBuffer()
      packet.write(buffer)
      return buffer.asInputStream()
    }
  }
}
