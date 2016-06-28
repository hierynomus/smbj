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
package com.hierynomus.mserref;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-ERREF].pdf 2.3.1 NTSTATUS values
 *
 * Subset of the possible values which are useful for SMB2 communication
 */
public enum NtStatus implements EnumWithValue<NtStatus> {
    STATUS_SUCCESS(0x00000000L),
    STATUS_TIMEOUT(0x00000102L),
    STATUS_PENDING(0x00000103L),
    STATUS_BUFFER_OVERFLOW(0x80000005L),
    STATUS_END_OF_FILE(0xC0000011L),
    STATUS_FILE_IS_A_DIRECTORY(0xC00000BAL),
    STATUS_NETWORK_NAME_DELETED(0xC00000C9L),
    STATUS_INVALID_PARAMETER(0xC000000DL),
    STATUS_MORE_PROCESSING_REQUIRED(0xC0000016L),
    STATUS_ACCESS_DENIED(0xC0000022L),
    STATUS_OBJECT_NAME_INVALID(0xC0000033L),
    STATUS_OBJECT_NAME_NOT_FOUND(0xC0000034L),
    STATUS_OBJECT_NAME_COLLISION(0xC0000035L),
    STATUS_OBJECT_PATH_NOT_FOUND(0xC000003AL),
    STATUS_LOGON_FAILURE(0xC000006DL),
    STATUS_PASSWORD_EXPIRED(0xC0000071L),
    STATUS_INSUFFICIENT_RESOURCES(0xC000009AL),
    STATUS_NOT_SUPPORTED(0xC00000BBL),
    STATUS_BAD_NETWORK_NAME(0xC00000CCL),
    STATUS_REQUEST_NOT_ACCEPTED(0xC00000D0L),
    STATUS_NET_WRITE_FAULT(0xC00000D2L),
    STATUS_NOT_SAME_DEVICE(0xC00000D4L),
    STATUS_FILE_RENAMED(0xC00000D5L),
    STATUS_OPLOCK_NOT_GRANTED(0xC00000E2L),
    STATUS_INTERNAL_ERROR(0xC00000E5L),
    STATUS_UNEXPECTED_IO_ERROR(0xC00000E9L),
    STATUS_DIRECTORY_NOT_EMPTY(0xC0000101L),
    STATUS_NOT_A_DIRECTORY(0xC0000103L),
    STATUS_NAME_TOO_LONG(0xC0000106L),
    STATUS_FILES_OPEN(0xC0000107L),
    STATUS_CONNECTION_IN_USE(0xC0000108L),
    STATUS_NOTIFY_CLEANUP(0x0000010BL),
    STATUS_NOTIFY_ENUM_DIR(0x0000010CL),
    STATUS_TOO_MANY_OPENED_FILES(0xC000011FL),
    STATUS_CANNOT_DELETE(0xC0000121L),
    STATUS_FILE_DELETED(0xC0000123L),
    STATUS_FILE_CLOSED(0xC0000128L),
    STATUS_OPEN_FAILED(0xC0000136L),
    STATUS_TOO_MANY_SIDS(0xC000017EL),
    STATUS_USER_SESSION_DELETED(0xC0000203L),
    STATUS_CONNECTION_DISCONNECTED(0xC000020CL),
    STATUS_CONNECTION_RESET(0xC000020DL),
    STATUS_NOT_FOUND(0xC0000225L),
    STATUS_PATH_NOT_COVERED(0xC0000257L),
    STATUS_RETRY(0xC000022DL),
    STATUS_DFS_UNAVAILABLE(0xC000026DL),
    STATUS_FILE_ENCRYPTED(0xC0000293L),
    STATUS_NETWORK_SESSION_EXPIRED(0xC000035CL),
    UNKNOWN(0xFFFFFFFFL);

    private long value;

    NtStatus(long val) {
        value = val;
    }

    @Override
    public long getValue() {
        return value;
    }

    public boolean isSuccess() {
        return (value >>> 30) == 0;
    }

    public boolean isError() {
        return (value >>> 30) == 0x3;
    }
}
