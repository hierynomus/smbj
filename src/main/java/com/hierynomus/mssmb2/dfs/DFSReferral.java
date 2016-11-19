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
package com.hierynomus.mssmb2.dfs;

import java.util.ArrayList;
import java.util.List;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

public class DFSReferral {
    int versionNumber;
    int pathConsumed;
    long ttl;
//    String serverName;   // Server
//    String shareName;    // Share
    // The ServerType field MUST be set to 0x0001 if root targets are returned. In all other cases, the ServerType 
    // field MUST be set to 0x0000.
    int serverType;
    public static int SERVERTYPE_LINK = 0x0000;
    public static int SERVERTYPE_ROOT = 0x0001;
    String link;
    String path;
    int proximity;
    int timeToLive;
    String dfsPath;
    String dfsAlternatePath;
//    String networkAddress;
    String specialName;
    List<String> expandedNames;
    
    public DFSReferral()
    {
    }

    public String toString() {
        return "DFSReferral[pathConsumed=" + pathConsumed +
//            ",serverName=" + serverName +
//            ",shareName=" + shareName +
            ",link=" + link +
            ",path=" + path +
            ",ttl=" + ttl + "]";
    }
    public static DFSReferral read(SMBBuffer buffer) throws BufferException {
        DFSReferral dfsr = new DFSReferral();
        dfsr.readRef(buffer);
        return dfsr;
    }

    private void readRef(SMBBuffer buffer) throws BufferException {
        int versionNumber, size, referralEntryFlags, dfsPathOffset, dfsAlternatePathOffset, networkAddressOffset;
        int start, specialNameOffset, numberOfExpandedNames, expandedNameOffset;
        int r;
        start = buffer.rpos();
        versionNumber = buffer.readUInt16();
        size = buffer.readUInt16();
        serverType = buffer.readUInt16();
        referralEntryFlags = buffer.readUInt16();
        
        switch(versionNumber) {
        case 1:
            path = buffer.readZString();
            break;
        case 2:
            proximity = buffer.readUInt32AsInt();
            ttl = buffer.readUInt32AsInt();
            dfsPathOffset = buffer.readUInt16();
            dfsAlternatePathOffset = buffer.readUInt16();
            networkAddressOffset = buffer.readUInt16();
            r = buffer.rpos();
            buffer.rpos(start+dfsPathOffset);
            dfsPath = buffer.readZString();
            buffer.rpos(start+dfsAlternatePathOffset);
            dfsAlternatePath = buffer.readZString();
            buffer.rpos(start+networkAddressOffset);
            path = buffer.readZString();
            
            buffer.rpos(r+size);
            break;
        case 3:
        case 4:
            ttl = buffer.readUInt32AsInt();
            if ((referralEntryFlags & 0x0002) == 0) {
                dfsPathOffset = buffer.readUInt16();
                dfsAlternatePathOffset = buffer.readUInt16();
                networkAddressOffset = buffer.readUInt16();
                buffer.readUInt16(); // skip GUID
                //TODO handle offsets. load strings.
            } else {
                specialNameOffset = buffer.readUInt16();
                numberOfExpandedNames = buffer.readUInt16();
                expandedNameOffset = buffer.readUInt16();
                r = buffer.rpos();
                buffer.rpos(start+specialNameOffset);
                specialName = buffer.readZString();
                buffer.rpos(start+expandedNameOffset);
                expandedNames = new ArrayList<String>(numberOfExpandedNames);
                for (int i=0; i<numberOfExpandedNames; i++) {
                    expandedNames.add(buffer.readZString());
                }
                buffer.rpos(r+size);
            }
            break;
        default:
            // TODO error
        }
    }

//    class DFSReferral_V1 {
//        int versionNumber;
//        int size;
//        int serverType;
//        int referralEntryFlags;
//        String shareName;
//    }
//    class DFSReferral_V2 {
//        int versionNumber;
//        int size;
//        int serverType;
//        int referralEntryFlags;
//        int proximity;
//        int timeToLive;
//        int dfsPathOffset;
//        int dfsAlternatePathOffset;
//        int networkAddressOffset;
//        //...
//    }
//    class DFSReferral_V3 {
//        int versionNumber;
//        int size;
//        int serverType;
//        int referralEntryFlags;
//        int timeToLive;
//    
//    }
//    class DFSReferral_V4 {
//        int versionNumber;
//        int size;
//        int serverType;
//        int referralEntryFlags;
//        int timeToLive;
//    }
}
