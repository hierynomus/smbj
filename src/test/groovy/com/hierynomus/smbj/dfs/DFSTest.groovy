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

import com.hierynomus.mssmb2.dfs.DFS;
import com.hierynomus.mssmb2.dfs.DFSException;
import com.hierynomus.mssmb2.dfs.DFS.ReferralResult;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.DefaultConfig
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.transport.TransportException;
import com.hierynomus.smbj.transport.TransportLayer;
import com.hierynomus.smbj.auth.AuthenticationContext

import spock.lang.Specification

class DFSTest  extends Specification {
    def "should resolve dfs for a path"() {
        given:
        def transport = Mock(TransportLayer)
        def bus = new SMBEventBus()
        def connection = Stub(Connection, constructorArgs: [new DefaultConfig(),transport,bus]) {
            getRemoteHostname() >> "domain"
        }
        def auth = new AuthenticationContext("username","password".toCharArray(),"domain")
        def session = new Session(123,connection,auth,bus,false)
        def path = new SmbPath("domain","share")
        
        when:
        DFS.resolveDFS(session, path)
            
        then:
        with(path) {
            domain=="fileserver"
            share=="fileshare"
        }
    }
     
}
