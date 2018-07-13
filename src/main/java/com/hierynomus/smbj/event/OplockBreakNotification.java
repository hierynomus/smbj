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
package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;

/***
 * Event for notifying the oplock break notification for corresponding fileId
 */
public class OplockBreakNotification extends AbstractAsyncNotification implements SMBEvent {

    private SMB2OplockBreakLevel oplockLevel;
    private SMB2FileId fileId;

    public OplockBreakNotification(SMB2OplockBreakLevel oplockLevel, SMB2FileId fileId) {
        // will always getting 0 for sessionId and treeId for oplock break notification.
        super(0L, 0L);
        this.oplockLevel = oplockLevel;
        this.fileId = fileId;
    }

    public SMB2OplockBreakLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
