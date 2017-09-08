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

public class SMB2GetDFSReferralExRequest {
    private int maxReferralLevel;
    private int requestFlags;
    private String requestFileName;
    private String siteName;

    enum RequestFlags {
        FLAGS_SITENAMEPRESENT(0x1);

        private int value;

        RequestFlags(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public SMB2GetDFSReferralExRequest(String path) {
        maxReferralLevel = 0;
        requestFlags = 0;
        requestFileName = path;
        siteName = null;
    }

    public SMB2GetDFSReferralExRequest(String path, String site) {
        maxReferralLevel = 0;
        requestFlags = RequestFlags.FLAGS_SITENAMEPRESENT.getValue();
        requestFileName = path;
        siteName = site;
    }

    public void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(maxReferralLevel);
        buffer.putUInt16(requestFlags);

        if ((requestFlags & RequestFlags.FLAGS_SITENAMEPRESENT.getValue()) != 0) {
            buffer.putUInt32(requestFileName.length() + 2 + siteName.length() + 2);
        } else {
            buffer.putUInt32(requestFileName.length() + 2);
        }

        buffer.putStringLengthUInt16(requestFileName);
        buffer.putString(requestFileName);

        if ((requestFlags & RequestFlags.FLAGS_SITENAMEPRESENT.getValue()) != 0) {
            buffer.putStringLengthUInt16(requestFileName);
            buffer.putString(requestFileName);
        }
    }

}
