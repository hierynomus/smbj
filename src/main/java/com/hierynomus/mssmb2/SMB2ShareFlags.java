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
package com.hierynomus.mssmb2;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-SMB2].pdf 2.2.10 TREE_CONNECT Response ShareFlags
 */
public enum SMB2ShareFlags implements EnumWithValue<SMB2ShareFlags> {
    SMB2_SHAREFLAG_MANUAL_CACHING(0x00000000L),
    SMB2_SHAREFLAG_AUTO_CACHING(0x00000010L),
    SMB2_SHAREFLAG_VDO_CACHING(0x00000020L),
    SMB2_SHAREFLAG_NO_CACHING(0x00000030L),
    SMB2_SHAREFLAG_DFS(0x00000001L),
    SMB2_SHAREFLAG_DFS_ROOT(0x00000002L),
    SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS(0x00000100L),
    SMB2_SHAREFLAG_FORCE_SHARED_DELETE(0x00000200L),
    SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING(0x00000400),
    SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM(0x00000800),
    SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK(0x00001000),
    SMB2_SHAREFLAG_ENABLE_HASH_V1(0x00002000),
    SMB2_SHAREFLAG_ENABLE_HASH_V2(0x00004000L),
    SMB2_SHAREFLAG_ENCRYPT_DATA(0x00008000L),
    SMB2_SHAREFLAG_IDENTITY_REMOTING(0x00040000L);

    private long value;

    SMB2ShareFlags(long value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return value;
    }
}
