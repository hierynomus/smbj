/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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
package com.hierynomus.smbj.smb2;

/**
 * [MS-SMB2].pdf 2.2.1.1 / 2.2.1.2
 * Message Command Code(s)
 */
public enum SMB2MessageCommandCode {
    SMB2_NEGOTIATE(0x0),
    SMB2_SESSION_SETUP(0x01),
    SMB2_LOGOFF(0x02),
    SMB2_TREE_CONNECT(0x03),
    SMB2_TREE_DISCONNECT(0x04),
    SMB2_CREATE(0x05),
    SMB2_CLOSE(0x06),
    SMB2_FLUSH(0x07),
    SMB2_READ(0x08),
    SMB2_WRITE(0x09),
    SMB2_LOCK(0x0A),
    SMB2_IOCTL(0x0B),
    SMB2_CANCEL(0x0C),
    SMB2_ECHO(0x0D),
    SMB2_QUERY_DIRECTORY(0x0E),
    SMB2_CHANGE_NOTIFY(0x0F),
    SMB2_QUERY_INFO(0x10),
    SMB2_SET_INFO(0x11),
    SMB2_OPLOCK_BREAK(0x12);

    private static final SMB2MessageCommandCode[] cache;

    static {
        cache = new SMB2MessageCommandCode[19];
        for (SMB2MessageCommandCode smb2MessageCommandCode : values()) {
            cache[smb2MessageCommandCode.getValue()] = smb2MessageCommandCode;
        }
    }

    private int value;

    SMB2MessageCommandCode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SMB2MessageCommandCode lookup(int value) {
        return cache[value];
    }
}
