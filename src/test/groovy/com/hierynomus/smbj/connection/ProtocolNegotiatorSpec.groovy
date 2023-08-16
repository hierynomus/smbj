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

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest
import com.hierynomus.mssmb2.messages.negotiate.SMB2EncryptionCapabilities
import com.hierynomus.mssmb2.messages.negotiate.SMB2PreauthIntegrityCapabilities
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.event.ConnectionClosed
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import spock.lang.Specification

class ProtocolNegotiatorSpec extends Specification {
  def bus = new SMBEventBus()

  private SmbConfig buildConfig(SmbConfig.Builder builder, packetProcessor) {
    builder
      .withTransportLayerFactory(new StubTransportLayerFactory(new DefaultPacketProcessor().wrap(packetProcessor)))
      .withAuthenticators(new StubAuthenticator.Factory())
      .build()
  }


  def "should not add SMB2EncryptionCapabilities to SMB2NegotiateRequest if encryptData is false"() {
    def r = _
    given:
    def config = buildConfig(SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1).withEncryptData(false), { req ->
      req = req.packet
      if (req instanceof SMB2NegotiateRequest) {
        r = req
        return null
      }
    })
    def client = new SMBClient(config, bus)

    when:
    def connect = client.connect("localhost")

    then:
    r.negotiateContextList.size() == 1
    r.negotiateContextList.get(0) instanceof SMB2PreauthIntegrityCapabilities
  }

  def "should add SMB2EncryptionCapabilities to SMB2NegotiateRequest if encryptData is true"() {
    def r = _
    given:
    def config = buildConfig(SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1).withEncryptData(true), { req ->
      req = req.packet
      if (req instanceof SMB2NegotiateRequest) {
        r = req
        return null
      }
    })
    def client = new SMBClient(config, bus)

    when:
    def connect = client.connect("localhost")

    then:
    r.negotiateContextList.size() == 2
    r.negotiateContextList.get(0) instanceof SMB2PreauthIntegrityCapabilities
    r.negotiateContextList.get(1) instanceof SMB2EncryptionCapabilities
  }

}
