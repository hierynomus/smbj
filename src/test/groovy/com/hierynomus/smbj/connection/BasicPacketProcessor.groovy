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
package com.hierynomus.smbj.connection

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2ShareCapabilities
import com.hierynomus.mssmb2.messages.*

class BasicPacketProcessor {
  private Closure<SMB2Packet> processPacket = { SMB2Packet req ->
    def resp = null
    if (req instanceof SMB2NegotiateRequest) {
      resp = negotiateResponse()
    } else if (req instanceof SMB2SessionSetup) {
      resp = sessionSetupResponse()
    } else if (req instanceof SMB2Logoff) {
      resp = logoffResponse()
    } else if (req instanceof SMB2TreeConnectRequest) {
      resp = connectResponse()
    } else if (req instanceof SMB2TreeDisconnect) {
      resp = disconnectResponse()
    }
    return resp
  }

  BasicPacketProcessor(Closure<SMB2Packet> processPacket) {
    addBehaviour(processPacket)
  }

  SMB2Packet processPacket(SMB2Packet req) {
    def resp = processPacket.call(req)
    if (resp == null) {
      throw new RuntimeException("COuld not find pre-recorded response for ${req}")
    }
    resp.header.message = req.header.message
    return resp
  }

  def addBehaviour(Closure<SMB2Packet> processPacket) {
    def originalProcessor = this.processPacket
    this.processPacket = { SMB2Packet packet ->
      def resp = processPacket.call(packet)
      if (resp == null) {
        resp = originalProcessor.call(packet)
      }
      return resp
    }
  }

  private static SMB2Packet negotiateResponse() {
    def response = new SMB2NegotiateResponse()
    response.header.message = SMB2MessageCommandCode.SMB2_NEGOTIATE
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response.dialect = SMB2Dialect.SMB_2_1
    response.systemTime = FileTime.now();
    response
  }

  private static SMB2Packet sessionSetupResponse() {
    def response = new SMB2SessionSetup()
    response.header.message = SMB2MessageCommandCode.SMB2_SESSION_SETUP
    response.header.sessionId = 1
    response.securityBuffer = new byte[16]
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response.sessionFlags = EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags)
    response
  }

  private static SMB2Packet logoffResponse() {
    def response = new SMB2Logoff()
    response.header.message = SMB2MessageCommandCode.SMB2_LOGOFF
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response
  }

  private static SMB2Packet connectResponse() {
    def response = new SMB2TreeConnectResponse()
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response.capabilities = EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS)
    response.shareType = 0x01 as byte
    response
  }

  private static SMB2Packet disconnectResponse() {
    def response = new SMB2TreeDisconnect()
    response.header.statusCode = NtStatus.STATUS_SUCCESS.value
    response
  }
}
