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
package com.hierynomus.msdfsc.messages;

import com.hierynomus.smb.SMBBuffer;

import java.nio.charset.StandardCharsets;

/**
 * [MS-DFSC].pdf 2.2.2 REQ_GET_DFS_REFERRAL
 */
public class SMB2GetDFSReferralRequest {

    private String requestFileName;
    
    public SMB2GetDFSReferralRequest(String path) {
        requestFileName = path;
    }
    
    public void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(4); // MaxReferralLevel (2 bytes)
        buffer.putNullTerminatedString(requestFileName, StandardCharsets.UTF_16); // RequestFileName (variable)
    }
}
