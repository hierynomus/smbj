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
package com.hierynomus.smbj.event.handler;

import com.hierynomus.smbj.event.AsyncCreateRequestNotification;
import com.hierynomus.smbj.event.AsyncCreateResponseNotification;
import com.hierynomus.smbj.event.OplockBreakNotification;

public interface NotificationHandler {
    // TODO: add user reference property to allow user to check same NotificationHandler or not.
    void handleAsyncCreateRequestNotification(AsyncCreateRequestNotification asyncCreateRequestNotification);
    void handleAsyncCreateResponseNotification(AsyncCreateResponseNotification asyncCreateResponseNotification);
    void handleOplockBreakNotification(OplockBreakNotification oplockBreakNotification);
}
