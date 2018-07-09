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
package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.SMB2Packet;

public abstract class SMB2OplockBreak extends SMB2Packet {

    protected SMB2OplockBreakLevel oplockLevel;
    protected SMB2FileId fileId;

    protected SMB2OplockBreak() {
        super();
    }

    protected SMB2OplockBreak(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId) {
        super(structureSize, dialect, messageType, sessionId);
    }

    protected SMB2OplockBreak(int structureSize, SMB2Dialect dialect, SMB2MessageCommandCode messageType, long sessionId, long treeId) {
        super(structureSize, dialect, messageType, sessionId, treeId);
    }

    public SMB2OplockBreakLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

}
