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
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;

import java.util.concurrent.Future;

/***
 * Event for notifying the fileId and CreateResponseFuture to corresponding messageId on AysncCreate
 */
public class AsyncCreateResponseNotification implements SMBEvent, AsyncNotification {

    private long messageId;
    private SMB2FileId fileId;
    private Future<SMB2CreateResponse> future;

    public AsyncCreateResponseNotification(long messageId, SMB2FileId fileId, Future<SMB2CreateResponse> future) {
        this.messageId = messageId;
        this.fileId = fileId;
        this.future = future;
    }

    public long getMessageId() {
        return messageId;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public Future<SMB2CreateResponse> getFuture() {
        return future;
    }
}
