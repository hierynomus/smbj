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

import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2ShareCapabilities
import com.hierynomus.mssmb2.messages.*

class BasicPacketProcessor {
  private Closure<SMB2Packet> processPacket

  BasicPacketProcessor(Closure<SMB2Packet> processPacket) {
    this.processPacket = processPacket
  }

  SMB2Packet processPacket(SMB2Packet req) {
    def resp = processPacket.call(req)
    if (resp == null) {
      if (req instanceof SMB2NegotiateRequest)
        resp = negotiateResponse()
      if (req instanceof SMB2SessionSetup)
        resp = sessionSetupResponse()
      if (req instanceof SMB2Logoff)
        resp = logoffResponse()
      if (req instanceof SMB2TreeConnectRequest)
        resp = connectResponse()
      if (req instanceof SMB2TreeDisconnect)
        resp = disconnectResponse()
    }
    resp.header.message = req.header.message
    return resp
  }

  private static SMB2Packet negotiateResponse() {
    def response = new SMB2NegotiateResponse()
    response.header.message = SMB2MessageCommandCode.SMB2_NEGOTIATE
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }

  private static SMB2Packet sessionSetupResponse() {
    def response = new SMB2SessionSetup()
    response.header.message = SMB2MessageCommandCode.SMB2_SESSION_SETUP
    response.header.sessionId = 1
    response.securityBuffer = new byte[16]
    response.header.status = NtStatus.STATUS_SUCCESS
    response.sessionFlags = EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags)
    response
  }

  private static SMB2Packet logoffResponse() {
    def response = new SMB2Logoff()
    response.header.message = SMB2MessageCommandCode.SMB2_LOGOFF
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }

  private static SMB2Packet connectResponse() {
    def response = new SMB2TreeConnectResponse()
    response.header.status = NtStatus.STATUS_SUCCESS
    response.capabilities = EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS)
    response.shareType = 0x01 as byte
    response
  }

  private static SMB2Packet disconnectResponse() {
    def response = new SMB2TreeDisconnect()
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }
}
