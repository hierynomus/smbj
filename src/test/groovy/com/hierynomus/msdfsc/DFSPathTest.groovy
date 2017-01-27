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

package com.hierynomus.msdfsc;

import static org.junit.Assert.*;

import org.junit.Test;

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

class DFSPathTest extends Specification {


    def "test parsePath typical path"() {
        def out;
        when:
        out = DFS.parsePath("\\a\\b\\c\\d");
        
        then:
        out.length == 4;
        out[0]=="a";
        out[1]=="b";
        out[2]=="c";
        out[3]=="d";
    }
    
    def "test parsePath starts with double slash"() {
        def out;
        when:
        out = DFS.parsePath("\\\\a\\b\\c\\d");
        
        then:
        out.length == 4;
        out[0]=="a";
        out[1]=="b";
        out[2]=="c";
        out[3]=="d";
    }
    def "test parsePath starts with no slash"() {
        def out;
        when:
        out = DFS.parsePath("a\\b\\c\\d");
        
        then:
        out.length == 4;
        out[0]=="a";
        out[1]=="b";
        out[2]=="c";
        out[3]=="d";
    }
    def "test parsePath single element"() {
        def out;
        when:
        out = DFS.parsePath("a");
        
        then:
        out.length == 1;
        out[0]=="a";
    }
    
    def "test normalizePath typical path"() {
        def out;
        when:
        out = DFS.normalizePath("\\a\\b\\c\\d");
        
        then:
        out=="\\a\\b\\c\\d";
    }
    
    def "test normalizePath starts with double slash"() {
        def out;
        when:
        out = DFS.normalizePath("\\\\a\\b\\c\\d");
        
        then:
        out=="\\a\\b\\c\\d";
    }
    def "test normalizePath single element"() {
        def out;
        when:
        out = DFS.normalizePath("\\a");
        
        then:
        out=="\\a";
    }
}
