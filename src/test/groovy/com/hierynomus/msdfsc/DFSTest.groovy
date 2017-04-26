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
package com.hierynomus.msdfsc

import com.hierynomus.msdfsc.messages.DFSReferral
import com.hierynomus.msdfsc.messages.DFSReferralV34
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralResponse
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ShareCapabilities
import com.hierynomus.mssmb2.messages.*
import com.hierynomus.security.jce.JceSecurityProvider
import com.hierynomus.smbj.DefaultConfig
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.common.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.NegotiatedProtocol
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.transport.TransportLayer
import spock.lang.Specification

import java.nio.charset.StandardCharsets
import java.util.concurrent.Future

class DFSTest extends Specification {
  def "should resolve dfs for a path"() {
    given:
    def connection
    def client = Stub(SMBClient) {
      connect(_) >> connection
      connect(_, _) >> connection
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000, 1000, 1000, false)

    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "10.0.0.10"
      getRemotePort() >> 445
      getNegotiatedProtocol() >> protocol
      send(_ as SMB2TreeConnectRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeConnectResponse();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
              response.setShareType((byte) 0x01);
              response
            }
          }
      }
      send(_ as SMB2TreeDisconnect) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeDisconnect();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      send(_ as SMB2IoctlRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2IoctlResponse()
              response.setOutputBuffer("260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex())

              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
    }

    def auth = new AuthenticationContext("username", "password".toCharArray(), "domain.com")
    def session = new DFSSession(123, connection, auth, bus, false, new JceSecurityProvider())
    def path = new SmbPath("10.0.0.10", "Sales")

    when:
    def resolvedPath = session.resolver.resolve(session, path.toUncPath())

    then:
    with(SmbPath.parse(resolvedPath)) {
      hostname == "SERVERHOST"
      shareName == "Sales"
    }
  }

  def "testdomain"() {
    given:
    def destination = "SERVERHOST"
    def connection
    def session
    def client = Stub(SMBClient) {
      connect(_) >> { String host -> connection }
      connect(_, _) >> { String host, int port ->
        connection
      }
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000, 1000, 1000, false)

    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "10.0.0.10"
      getRemotePort() >> 445
      getNegotiatedProtocol() >> protocol
      getClient() >> client
      authenticate(_) >> { AuthenticationContext authContext ->
        session
      }
      send(_ as SMB2TreeConnectRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeConnectResponse();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
              response.setShareType((byte) 0x01);
              response
            }
          }
      }
      send(_ as SMB2TreeDisconnect) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeDisconnect();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      send(_ as SMB2IoctlRequest) >> {
        SMB2IoctlRequest request ->
          Mock(Future) {
            get() >> {
              def d = request.inputData[2..-1] as byte[]
              def dbuf = new SMBBuffer(d);
              def path = dbuf.readNullTerminatedString(StandardCharsets.UTF_16);
              def response = new SMB2IoctlResponse()
              def referralResponse
              if (path == "domain.com") {
                // the dc request
                def referralEntry = new DFSReferralV34(4, DFSReferral.ServerType.ROOT, 2, 1000, "domain.com", [destination])
                referralResponse = new SMB2GetDFSReferralResponse("\\domain.com", 0, EnumSet.noneOf(SMB2GetDFSReferralResponse.ReferralHeaderFlags.class), [referralEntry])
              } else if (path == "\\domain.com\\Sales") {
                //the root request
                def referralEntry = new DFSReferralV34(4, DFSReferral.ServerType.ROOT, 0, 1000, "\\domain.com\\Sales", "\\domain.com\\Sales", "\\SERVERHOST\\Sales")
                referralResponse = new SMB2GetDFSReferralResponse(path, 0, EnumSet.noneOf(SMB2GetDFSReferralResponse.ReferralHeaderFlags.class), [referralEntry])
              }
              def buf = new SMBBuffer()
              referralResponse.writeTo(buf)

              response.setOutputBuffer(buf.getCompactData())
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
    }

    def auth = new AuthenticationContext("username", "password".toCharArray(), "domain.com")
    session = new DFSSession(123, connection, auth, bus, false, new JceSecurityProvider())
    def path = new SmbPath("domain.com", "Sales")

    when:
    def newPath = session.resolver.resolve(session, path.toUncPath())

    then:
    with(SmbPath.parse(newPath)) {
      hostname == destination
      shareName == "Sales"
    }
  }

  def testResolvePath() {
    def connection
    def session
    def client = Stub(SMBClient) {
      connect(_) >> { String host -> connection }
      connect(_, _) >> { String host, int port ->
        connection
      }
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000, 1000, 1000, false)
    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "10.0.0.10"
      getRemotePort() >> 445
      getClient() >> client
      getNegotiatedProtocol() >> protocol
      send(_ as SMB2TreeConnectRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeConnectResponse();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
              response.setShareType((byte) 0x01);
              response
            }
          }
      }
      send(_ as SMB2TreeDisconnect) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeDisconnect();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      send(_ as SMB2IoctlRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2IoctlResponse()
              response.setOutputBuffer("260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex());
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      authenticate(_) >> { AuthenticationContext auth ->
        new DFSSession(0, connection, auth, bus, false, new JceSecurityProvider())
      }
    }
    AuthenticationContext auth = new AuthenticationContext("username", "password".toCharArray(), "domain.com");
    session = new DFSSession(0, connection, auth, bus, false, new JceSecurityProvider());//TODO fill me in
    def path = SmbPath.parse("\\10.0.0.10\\Sales")

    when:
    def newPath = session.resolver.resolve(session, path.toUncPath());

    then:
    newPath.toString() == "\\SERVERHOST\\Sales"

  }
  // test resolve with link resolve
  def "testlink"() {
    given:
    def destination = "SERVERHOST"
    def connection
    def session
    def client = Stub(SMBClient) {
      connect(_) >> { String host -> connection }
      connect(_, _) >> { String host, int port ->
        connection
      }
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000, 1000, 1000, false)

    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "10.0.0.10"
      getRemotePort() >> 445
      getNegotiatedProtocol() >> protocol
      getClient() >> client
      authenticate(_) >> { AuthenticationContext authContext ->
        session
      }
      send(_ as SMB2TreeConnectRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeConnectResponse();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
              response.setShareType((byte) 0x01);
              response
            }
          }
      }
      send(_ as SMB2TreeDisconnect) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeDisconnect();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      send(_ as SMB2IoctlRequest) >> {
        SMB2IoctlRequest request ->
          Mock(Future) {
            get() >> {
              def d = request.inputData[2..-1] as byte[]
              def dbuf = new SMBBuffer(d);
              def path = dbuf.readNullTerminatedString(StandardCharsets.UTF_16);
              def response = new SMB2IoctlResponse()
              def referralResponse
              if (path == "\\SERVERHOST\\Sales\\NorthAmerica") {
                //the root request
                def referralEntry = new DFSReferralV34(4, DFSReferral.ServerType.ROOT, 0, 1000, "\\SERVERHOST\\Sales\\NorthAmerica", "\\SERVERHOST\\Sales\\NorthAmerica", "\\SERVERHOST\\Regions\\Region1")
                referralResponse = new SMB2GetDFSReferralResponse(path, 0, EnumSet.noneOf(SMB2GetDFSReferralResponse.ReferralHeaderFlags.class), [referralEntry])
              }
              def buf = new SMBBuffer();
              referralResponse.writeTo(buf);

              response.setOutputBuffer(buf.getCompactData())
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
    }

    def auth = new AuthenticationContext("username", "password".toCharArray(), "domain.com")
    session = new DFSSession(123, connection, auth, bus, false, new JceSecurityProvider())
    def path = new SmbPath("SERVERHOST", "Sales", "NorthAmerica")

    when:
    def newPath = SmbPath.parse(session.resolver.resolve(session, path.toUncPath()))

    then:
    newPath.hostname == "SERVERHOST"
    newPath.shareName == "Regions"
    newPath.path == "Region1"
  }

  // test resolve with link resolve
  def "testinterlink"() {
    given:
    def destination = "SERVERHOST"
    def connection
    def session
    def client = Stub(SMBClient) {
      connect(_) >> { String host -> connection }
      connect(_, _) >> { String host, int port ->
        connection
      }
    }
    def transport = Mock(TransportLayer)
    def bus = new SMBEventBus()
    def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000, 1000, 1000, false)

    connection = Stub(Connection, constructorArgs: [new DefaultConfig(), client, transport, bus]) {
      getRemoteHostname() >> "10.0.0.10"
      getRemotePort() >> 445
      getNegotiatedProtocol() >> protocol
      getClient() >> client
      authenticate(_) >> { AuthenticationContext authContext ->
        session
      }
      send(_ as SMB2TreeConnectRequest) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeConnectResponse();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
              response.setShareType((byte) 0x01);
              response
            }
          }
      }
      send(_ as SMB2TreeDisconnect) >> {
        c ->
          Mock(Future) {
            get() >> {
              def response = new SMB2TreeDisconnect();
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
      send(_ as SMB2IoctlRequest) >> {
        SMB2IoctlRequest request ->
          Mock(Future) {
            get() >> {
              def d = request.inputData[2..-1] as byte[]
              def dbuf = new SMBBuffer(d);
              def path = dbuf.readNullTerminatedString(StandardCharsets.UTF_16);
              def response = new SMB2IoctlResponse()
              def referralResponse

              if (path == "\\SERVERHOST\\Sales\\NorthAmerica") {
                //the root request
                def referralEntry = new DFSReferralV34(4, DFSReferral.ServerType.LINK, 0x4, 1000, "\\SERVERHOST\\Sales\\NorthAmerica", "\\SERVERHOST\\Sales\\NorthAmerica", "\\ALTER\\Regions\\Region1")
                referralResponse = new SMB2GetDFSReferralResponse(path, 0, EnumSet.noneOf(SMB2GetDFSReferralResponse.ReferralHeaderFlags.class), [referralEntry])
              }
              def buf = new SMBBuffer();
              referralResponse.writeTo(buf);

              response.setOutputBuffer(buf.getCompactData())
              response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
              response
            }
          }
      }
    }

    def auth = new AuthenticationContext("username", "password".toCharArray(), "domain.com")
    session = new DFSSession(123, connection, auth, bus, false, new JceSecurityProvider())
    def path = new SmbPath("SERVERHOST", "Sales", "NorthAmerica")

    when:
    def resolvedPath = SmbPath.parse(session.resolver.resolve(session, path.toUncPath()))

    then:
    resolvedPath.hostname == "ALTER"
    resolvedPath.shareName == "Regions"
    resolvedPath.path == "Region1"
  }

  // test resolve from not-covered error

  // test resolve with domain cache populated
  // test resolve with referral cache populated
}
