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
package com.hierynomus.msfscc;

import com.hierynomus.protocol.commons.EnumWithValue;

/**
 * [MS-FSCC].pdf 2.4 File Information Classes
 * [MS-SMB2].pdf 2.2.33 SMB2 QUERY_DIRECTORY - FileInformationClass
 */
public enum FileInformationClass implements EnumWithValue<FileInformationClass> {

    FileDirectoryInformation(0x01),
    FileFullDirectoryInformation(0x02),
    FileBothDirectoryInformation(0x03),
    FileBasicInformation(0x04),
    FileStandardInformation(0x05),
    FileInternalInformation(0x06),
    FileEaInformation(0x07),
    FileAccessInformation(0x08),
    FileNameInformation(0x09),
    FileRenameInformation(0x0A),
    FileLinkInformation(0x0B),
    FileNamesInformation(0x0C),
    FileDispositionInformation(0x0D),
    FilePositionInformation(0x0E),
    FileFullEaInformation(0x0F),
    FileModeInformation(0x10),
    FileAlignmentInformation(0x11),
    FileAllInformation(0x12),
    FileAllocationInformation(0x13),
    FileEndOfFileInformation(0x14),
    FileAlternateNameInformation(0x15),
    FileStreamInformation(0x16),
    FilePipeInformation(0x17),
    FilePipeLocalInformation(0x18),
    FilePipeRemoteInformation(0x19),
    FileMailslotQueryInformation(0x1A),
    FileMailslotSetInformation(0x1B),
    FileCompressionInformation(0x1C),
    FileObjectIdInformation(0x1D),
    FileCompletionInformation(0x1E),
    FileMoveClusterInformation(0x1F),
    FileQuotaInformation(0x20),
    FileReparsePointInformation(0x21),
    FileNetworkOpenInformation(0x22),
    FileAttributeTagInformation(0x23),
    FileTrackingInformation(0x24),
    FileIdBothDirectoryInformation(0x25),
    FileIdFullDirectoryInformation(0x26),
    FileValidDataLengthInformation(0x27),
    FileShortNameInformation(0x28),
    FileIoCompletionNotificationInformation(0x29),
    FileIoStatusBlockRangeInformation(0x2A),
    FileIoPriorityHintInformation(0x2B),
    FileSfioReserveInformationv(0x2C),
    FileSfioVolumeInformation(0x2D),
    FileHardLinkInformation(0x2E),
    FileProcessIdsUsingFileInformation(0x2F),
    FileNormalizedNameInformation(0x30),
    FileNetworkPhysicalNameInformation(0x31),
    FileIdGlobalTxDirectoryInformation(0x32),
    FileIsRemoteDeviceInformation(0x33),
    FileUnusedInformation(0x34),
    FileNumaNodeInformation(0x35),
    FileStandardLinkInformation(0x36),
    FileRemoteProtocolInformation(0x37),
    FileRenameInformationBypassAccessCheck(0x38),
    FileLinkInformationBypassAccessCheck(0x39),
    FileVolumeNameInformation(0x3A),
    FileIdInformation(0x3B),
    FileIdExtdDirectoryInformation(0x3C),
    FileReplaceCompletionInformation(0x3D),
    FileHardLinkFullIdInformation(0x3E),
    FileIdExtdBothDirectoryInformation(0x3F),
    FileMaximumInformation(0x40);

    private long value;

    FileInformationClass(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }
}
