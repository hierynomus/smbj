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
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.isSet;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.List;

import org.junit.Test;

import com.hierynomus.msdfsc.DFS;
import com.hierynomus.msdfsc.DFSException;
import com.hierynomus.msdfsc.DFSReferral;
import com.hierynomus.msdfsc.DFS.ReferralResult;
import com.hierynomus.msdfsc.SMB2GetDFSReferralResponse.ReferralHeaderFlags;
import com.hierynomus.msdfsc.SMB2GetDFSReferralResponse;
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
import com.hierynomus.smbj.common.SMBBuffer
import com.hierynomus.mssmb2.SMB2ShareCapabilities;

import spock.lang.Specification

class DFSTest extends Specification {
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
            getRemoteHostname() >> "10.0.0.10"
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
                        response.setOutputBuffer("260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex())
                        
                        response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
                        response
                    }
                }
            }
        }
        
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain.com")
        def session = new Session(123,connection,auth,bus,false)
        def SmbPath path = new SmbPath("10.0.0.10","Sales")

        when:
        DFS.resolveDFS(session, path)
        
        then:
        with(path) {
            hostname=="SERVERHOST"
            shareName=="Sales"
        }
    }
    
    def "testdomain" () {
        given:
        def destination = "SERVERHOST"
        def connection
        def session
        def client = Stub(SMBClient) {
            connect(_) >> { String host -> connection }
            connect(_,_) >> { String host, int port ->
                connection
            }
        }
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000,1000,1000,false)
    
        connection = Stub(Connection, constructorArgs: [new DefaultConfig(),client,transport,bus]) {
            getRemoteHostname() >> "10.0.0.10"
            getRemotePort() >> 445
            getNegotiatedProtocol() >> protocol
            getClient() >> client
            authenticate(_) >> {AuthenticationContext authContext -> 
                session
            }
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
                SMB2IoctlRequest request,k -> Mock(Future) {
                    get() >> {
                        def d = request.inputData[2..-1] as byte[]
                        def dbuf = new SMBBuffer(d);
                        def path = dbuf.readZString();
                        def response = new SMB2IoctlResponse()
                        def referralResponse
                        if (path=="domain.com") {
                            // the dc request
                            def referralEntry = new DFSReferral(
                                4,
                                1000,
                                DFSReferral.SERVERTYPE_ROOT,
                                2, // NameListReferral
                                "\\domain.com",
                                0,
                                destination,
                                destination,
                                "domain.com",
                                [destination] as ArrayList
                            );
                            referralResponse = new SMB2GetDFSReferralResponse(
                                "\\domain.com",
                                0,
                                1,
                                0,
                                [referralEntry] as ArrayList,
                                "")
                        } else if (path=="\\domain.com\\Sales"){
                            //the root request
                            def referralEntry = new DFSReferral(
                                4,    // referral version
                                1000, // ttl
                                DFSReferral.SERVERTYPE_ROOT,
                                0,    // referralEntryFlags: non-NameListReferral
                                "\\SERVERHOST\\Sales", // networkAddress
                                0,    // proximity
                                "\\domain.com\\Sales", // dfsPath
                                "\\domain.com\\Sales", // dfsAltPath
                                null, // no specialName
                                null  // no expandedNames
                            );
                            referralResponse = new SMB2GetDFSReferralResponse(
                                path,
                                0,
                                1,
                                0,
                                [referralEntry] as ArrayList,
                                "")
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
        
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain.com")
        session = new Session(123,connection,auth,bus,false)
        def path = new SmbPath("domain.com","Sales")

        when:
        DFS.resolveDFS(session, path)
        
        then:
        with(path) {
            hostname==destination
            shareName=="Sales"
        }
    }
    
    def testResolvePath() {
        def connection
        def session
        def client = Stub(SMBClient) {
            connect(_) >> { String host -> connection }
            connect(_,_) >> { String host, int port ->
                connection
            }
        }
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000,1000,1000,false)
        connection = Stub(Connection, constructorArgs: [new DefaultConfig(),client,transport,bus]) {
            getRemoteHostname() >> "10.0.0.10"
            getRemotePort() >> 445
            getClient() >> client
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
                        response.setOutputBuffer("260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex());
                        response.getHeader().setStatus(NtStatus.STATUS_SUCCESS)
                        response
                    }
                }
            }
            authenticate(_) >> { AuthenticationContext auth ->
                new Session(0, connection, auth, null, false);
            }
        }
        DFS dfs = new DFS();
        AuthenticationContext auth = new AuthenticationContext("username","password".toCharArray(),"domain.com");
        session = new Session(0, connection, auth, null, false);//TODO fill me in
        String path = "\\10.0.0.10\\Sales";
       
        when:
        def newPath = dfs.resolvePath(session, path);
        
        then:
        "\\SERVERHOST\\Sales"==newPath

    }
    // test resolve with link resolve
    def "testlink" () {
        given:
        def destination = "SERVERHOST"
        def connection
        def session
        def client = Stub(SMBClient) {
            connect(_) >> { String host -> connection }
            connect(_,_) >> { String host, int port ->
                connection
            }
        }
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000,1000,1000,false)
    
        connection = Stub(Connection, constructorArgs: [new DefaultConfig(),client,transport,bus]) {
            getRemoteHostname() >> "10.0.0.10"
            getRemotePort() >> 445
            getNegotiatedProtocol() >> protocol
            getClient() >> client
            authenticate(_) >> {AuthenticationContext authContext -> 
                session
            }
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
                SMB2IoctlRequest request,k -> Mock(Future) {
                    get() >> {
                        def d = request.inputData[2..-1] as byte[]
                        def dbuf = new SMBBuffer(d);
                        def path = dbuf.readZString();
                        def response = new SMB2IoctlResponse()
                        def referralResponse
                        if (path=="\\SERVERHOST\\Sales\\NorthAmerica"){
                            //the root request
                            def referralEntry = new DFSReferral(
                                4,    // referral version
                                1000, // ttl
                                DFSReferral.SERVERTYPE_ROOT,
                                0,    // referralEntryFlags: non-NameListReferral
                                "\\SERVERHOST\\Regions\\Region1", // networkAddress
                                0,    // proximity
                                "\\SERVERHOST\\Sales\\NorthAmerica", // dfsPath
                                "\\SERVERHOST\\Sales\\NorthAmerica", // dfsAltPath
                                null, // no specialName
                                null  // no expandedNames
                            );
                            referralResponse = new SMB2GetDFSReferralResponse(
                                path,
                                0,
                                1,
                                0,
                                [referralEntry] as ArrayList,
                                "")
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
        
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain.com")
        session = new Session(123,connection,auth,bus,false)
        def SmbPath path = new SmbPath("SERVERHOST","Sales","NorthAmerica")

        when:
            DFS.resolveDFS(session, path)
        
        then:
            path.hostname=="SERVERHOST"
            path.shareName=="Regions"
            path.path=="Region1"
    }
    
    // test resolve with link resolve
    def "testinterlink" () {
        given:
        def destination = "SERVERHOST"
        def connection
        def session
        def client = Stub(SMBClient) {
            connect(_) >> { String host -> connection }
            connect(_,_) >> { String host, int port ->
                connection
            }
        }
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def protocol = new NegotiatedProtocol(SMB2Dialect.SMB_2_1, 1000,1000,1000,false)

        connection = Stub(Connection, constructorArgs: [new DefaultConfig(),client,transport,bus]) {
            getRemoteHostname() >> "10.0.0.10"
            getRemotePort() >> 445
            getNegotiatedProtocol() >> protocol
            getClient() >> client
            authenticate(_) >> {AuthenticationContext authContext ->
                session
            }
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
                SMB2IoctlRequest request,k -> Mock(Future) {
                    get() >> {
                        def d = request.inputData[2..-1] as byte[]
                        def dbuf = new SMBBuffer(d);
                        def path = dbuf.readZString();
                        def response = new SMB2IoctlResponse()
                        def referralResponse
                        
                        if (path=="\\SERVERHOST\\Sales\\NorthAmerica") {
                            //the root request
                            def referralEntry = new DFSReferral(
                                4,    // referral version
                                1000, // ttl
                                DFSReferral.SERVERTYPE_LINK,
                                1, //ReferralServers
                                "\\ALTER\\Region1", // target networkAddress
                                0,    // proximity
                                "\\SERVERHOST\\Sales\\NorthAmerica", // dfsPath
                                "\\SERVERHOST\\Sales\\NorthAmerica", // dfsAltPath
                                null, // no specialName
                                null  // no expandedNames
                            );
                            referralResponse = new SMB2GetDFSReferralResponse(
                                path,
                                0,
                                1,
                                0,
                                [referralEntry] as ArrayList,
                                "")
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
        
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain.com")
        session = new Session(123,connection,auth,bus,false)
        def SmbPath path = new SmbPath("SERVERHOST","Sales","NorthAmerica")

        when:
            DFS.clearCaches();
            DFS.resolveDFS(session, path)
        
        then:
            path.hostname=="ALTER"
            path.shareName=="Regions"
            path.path=="Region1"
    }
    
    
    // test resolve from not-covered error

    // test resolve with domain cache populated
    // test resolve with referral cache populated
}