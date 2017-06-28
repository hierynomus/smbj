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
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2ShareCapabilities
import com.hierynomus.mssmb2.messages.SMB2Logoff
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.mssmb2.messages.SMB2SessionSetup
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect

class BasicPacketProcessor {
  private Closure<SMB2Packet> processPacket

  BasicPacketProcessor(Closure<SMB2Packet> processPacket) {
    this.processPacket = processPacket
  }

  SMB2Packet processPacket(SMB2Packet req) {
    if (req instanceof SMB2NegotiateRequest)
      return negotiateResponse()
    if (req instanceof SMB2SessionSetup)
      return sessionSetupResponse()
    if (req instanceof SMB2Logoff)
      return logoffResponse()
    if (req instanceof SMB2TreeConnectRequest)
      return connectResponse()
    if (req instanceof SMB2TreeDisconnect)
      return disconnectResponse()

    processPacket.call(req)
  }

  private SMB2Packet negotiateResponse() {
    def response = new SMB2NegotiateResponse()
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }

  private SMB2Packet sessionSetupResponse() {
    def response = new SMB2SessionSetup()
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }

  private SMB2Packet logoffResponse() {
    def response = new SMB2Logoff()
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }

  private SMB2Packet connectResponse() {
    def response = new SMB2TreeConnectResponse()
    response.header.status = NtStatus.STATUS_SUCCESS
    response.capabilities = EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS)
    response.shareType = 0x01 as byte
    response
  }

  private SMB2Packet disconnectResponse() {
    def response = new SMB2TreeDisconnect()
    response.header.status = NtStatus.STATUS_SUCCESS
    response
  }
}
