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

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import com.hierynomus.msdfsc.DFSReferral;
import com.hierynomus.msdfsc.SMB2GetDFSReferralResponse;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DFSTest{

    @Test 
    public void decodeDFSReferral() throws BufferException {
       String s = "260001000300000004002200010004002c01000022004a007200000000000000000000000000000000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00570049004e002d004e0051005500390049004f0042004500340056004a005c00530061006c00650073000000";
       SMBBuffer buf = new SMBBuffer(Hex.decode(s));
       SMB2GetDFSReferralResponse resp  = new SMB2GetDFSReferralResponse("\\52.53.184.91\\Sales");
       resp.read(buf);
       SMBBuffer buf2 = new SMBBuffer();
       resp.writeTo(buf2);
       buf.rpos(0);
       buf2.rpos(0);
       byte[] b1 = buf.getCompactData();
       byte[] b2 = buf2.getCompactData();
       assertTrue(Arrays.equals(b1,b2));
    }
    
    @Test
    public void encodeDFSReferralResponse() throws BufferException {
        DFSReferral referralEntry = new DFSReferral(4, 300, DFSReferral.SERVERTYPE_ROOT, 4, "\\WIN-NQU9IOBE4VJ\\Sales", 
                        "\\WIN-NQU9IOBE4VJ\\Sales", 0, "\\52.53.184.91\\sales", "\\52.53.184.91\\sales", null, null);
        
        DFSReferral[] referrals = new DFSReferral[]{referralEntry};
        
        SMB2GetDFSReferralResponse dfsRefResp = new SMB2GetDFSReferralResponse("\\WIN-NQU9IOBE4VJ\\Sales",
            38,
            1,
            3,
            Arrays.asList(referrals),
            "abc");
    
        SMBBuffer buf = new SMBBuffer();
        dfsRefResp.writeTo(buf);
        
        byte[] b = buf.getCompactData();
        
        String hex = new String(Hex.encode(b));

        assertEquals("260001000300000004002200010004002c01000022004a007200000000000000000000000000000000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00350032002e00350033002e003100380034002e00390031005c00730061006c006500730000005c00570049004e002d004e0051005500390049004f0042004500340056004a005c00530061006c00650073000000",
                        hex);

    }
    
    @Test
    public void testResolvePath() throws IOException, BufferException, DFSException {
        SMBClient client = new SMBClient();
        DFS dfs = new DFS();
        Connection connection = client.connect("hostname");
        AuthenticationContext auth = new AuthenticationContext("username","password".toCharArray(),"domain.com");
        Session session = new Session(0, connection, auth, null, false);//TODO fill me in
        String path = "\\domain.com\\Sales";
        String newPath = dfs.resolvePath(session, path);
        
        assertEquals("\\52.53.184.91\\sales",newPath);
    }
    // test resolve with domain cache populated
    // test resolve with referral cache populated
    // test resolve with link resolve
    // test resolve from not-covered error

}