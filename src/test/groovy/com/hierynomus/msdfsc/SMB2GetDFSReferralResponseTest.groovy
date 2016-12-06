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
import spock.lang.Specification;

import java.util.ArrayList;
import java.util.List;

import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

class SMB2GetDFSReferralResponseTest extends Specification  {

    def "encode dfs referral response root" () {
        when:
        def referralEntry = new DFSReferral();
        referralEntry.versionNumber = 4;
        referralEntry.serverType = DFSReferral.SERVERTYPE_ROOT;
        referralEntry.referralEntryFlags = 4;
        referralEntry.dfsPath = "\\10.0.0.10\\sales";
        referralEntry.dfsAlternatePath = "\\10.0.0.10\\sales";
        referralEntry.path = "\\SERVERHOST\\Sales";
        referralEntry.ttl = 300;
        
        def referrals = [referralEntry ] as ArrayList
        
        def dfsRefResp = new SMB2GetDFSReferralResponse("\\SERVERHOST\\Sales",
            38,
            1,
            3,
            referrals,
            "");
    
        def buf = new SMBBuffer();
        dfsRefResp.writeTo(buf);
        def data = buf.getCompactData();
        
        then:
        data=="260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex()
    }
    
    def "encode dfs referral response link" () {
        when:
        def referralEntry = new DFSReferral();
        referralEntry.versionNumber = 4;
        referralEntry.serverType = DFSReferral.SERVERTYPE_LINK;
        referralEntry.referralEntryFlags = 4;
        referralEntry.dfsPath = "\\10.0.0.10\\sales";
        referralEntry.dfsAlternatePath = "\\10.0.0.10\\sales";
        referralEntry.path = "\\SERVERHOST\\Sales";
        referralEntry.ttl = 300;
        
        def referrals = [referralEntry ] as ArrayList
        
        def dfsRefResp = new SMB2GetDFSReferralResponse("\\SERVERHOST\\Sales",
            38,
            1,
            3,
            referrals,
            "");
    
        def buf = new SMBBuffer();
        dfsRefResp.writeTo(buf);
        def data = buf.getCompactData();
        
        then:
        data=="260001000300000004002200000004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex()
    }

    def "encode dfs referral response domain" () {
        when:
        def referralEntry = new DFSReferral();
        referralEntry.versionNumber = 3;
        referralEntry.serverType = DFSReferral.SERVERTYPE_ROOT;
        referralEntry.referralEntryFlags = 0x2;
        referralEntry.dfsPath = "\\SEVERHOST\\sales";
        referralEntry.dfsAlternatePath = "\\SERVERHOST\\sales";
        referralEntry.path = "\\DOMAIN";
        referralEntry.ttl = 300;
        referralEntry.specialName = "DOMAIN"
        referralEntry.expandedNames = ["SERVERHOST"] as ArrayList;
        
        def referrals = [referralEntry ] as ArrayList
        
        def dfsRefResp = new SMB2GetDFSReferralResponse("\\SERVERHOST\\Sales",
            38,
            1,
            3,
            referrals,
            "");
    
        def buf = new SMBBuffer();
        dfsRefResp.writeTo(buf);
        def data = buf.getCompactData();
        
        then:
        println data.encodeHex()
        println "260001000300000003002200010002002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000"
        data=="260001000300000003002200010002002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000".decodeHex()
    }
    
}
