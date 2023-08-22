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
package com.hierynomus.msfscc.fileinformation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

public class FileAllInformationTest {
    @Test
    public void shouldParseFileAllInformation() throws Exception {
        String hex = "80a79df99105d0013291af48c52dd2013291af48c52dd20136a3af48c52dd201800000000000000000001000000000003e46000000000000010000000000000087006f00010000000000000089001200000000000000000000000000000000002e0000005c006900660073005c006900730069005f006700610074006800650072005f0070006500720066002e0070007900";
        byte[] bytes = ByteArrayUtils.parseHex(hex);

        FileAllInformation info = FileInformationFactory.getDecoder(FileAllInformation.class)
                .read(new Buffer.PlainBuffer(bytes, Endian.LE));

        assertEquals(new FileTime(130610513710000000L), info.getBasicInformation().getCreationTime());
        assertEquals(new FileTime(131217664498438450L), info.getBasicInformation().getLastAccessTime());
        assertEquals(new FileTime(131217664498438450L), info.getBasicInformation().getLastWriteTime());
        assertEquals(new FileTime(131217664498443062L), info.getBasicInformation().getChangeTime());
        assertEquals(128, info.getBasicInformation().getFileAttributes());
        assertEquals(1048576L, info.getStandardInformation().getAllocationSize());
        assertEquals(17982L, info.getStandardInformation().getEndOfFile());
        assertEquals(1, info.getStandardInformation().getNumberOfLinks());
        assertFalse(info.getStandardInformation().isDeletePending());
        assertFalse(info.getStandardInformation().isDirectory());
        assertEquals(4302241927L, info.getInternalInformation().getIndexNumber());
        assertEquals(0, info.getEaInformation().getEaSize());
        assertEquals(1179785, info.getAccessInformation().getAccessFlags());
        assertEquals(0, info.getPositionInformation().getCurrentByteOffset());
        assertEquals(0, info.getModeInformation().getMode());
        assertEquals(0, info.getAlignmentInformation().getAlignmentRequirement());
        assertEquals("\\ifs\\isi_gather_perf.py", info.getNameInformation());
    }
}
