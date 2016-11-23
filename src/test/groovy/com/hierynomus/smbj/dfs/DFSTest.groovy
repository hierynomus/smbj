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
package com.hierynomus.smbj.dfs
import java.util.UUID;
import java.util.concurrent.Future;

import com.hierynomus.mssmb2.dfs.DFS;
import com.hierynomus.mssmb2.dfs.DFSException;
import com.hierynomus.mssmb2.dfs.DFS.ReferralResult;
import com.hierynomus.mssmb2.messages.SMB2IoctlResponse;
import com.hierynomus.mssmb2.messages.SMB2IoctlRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.DefaultConfig
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.Request;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.NegotiatedProtocol
import com.hierynomus.smbj.connection.Request
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;

import spock.lang.Specification

class DFSTest  extends Specification {
    def "should resolve dfs for a path"() {
        given:
        def connection
        def client = Stub(SMBClient) {
            connect(_) >> connection
            connect(_,_) >> connection
        }
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000,1000,1000,false)

        connection = Stub(Connection, constructorArgs: [new DefaultConfig(),client,transport,bus]) {
            getRemoteHostname() >> "52.53.184.91"
            getRemotePort() >> 445
            getNegotiatedProtocol() >> protocol
            send(_ as SMB2TreeConnectRequest,null) >> {
                c,k->Mock(Future) {
                    get() >> {
                        def response = new SMB2TreeConnectResponse();
                        response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
                        response.setCapabilities(EnumSet.of(SMB2ShareCapabilities.SMB2_SHARE_CAP_DFS));
                        response.setShareType((byte)0x01);
                        response
                    }
                }
            }
            send(_ as SMB2IoctlRequest,null) >> {
                c,k->Mock(Future) {
                    get() >> {
                        def response = new SMB2IoctlResponse()
                        response.setOutputBuffer("260001000300000004002200010004002c01000022004a007200000000000000000000000000000000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00570049004e002d004e0051005500390049004f0042004500340056004a005c00530061006c00650073000000".decodeHex())
                        response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
                        response
                    }
                }
            }
        }
        
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain")
        def session = new Session(123,connection,auth,bus,false)
        def path = new SmbPath("52.53.184.91","Sales")

        when:
        DFS.resolveDFS(session, path)
        System.out.println(path);
        
        then:
        with(path) {
            hostname=="WIN-NQU9IOBE4VJ"
            shareName=="Sales"
        }
    }
}