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
package com.hierynomus.msfscc.fileinformation

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.buffer.Buffer
import com.hierynomus.protocol.commons.buffer.Endian
import spock.lang.Specification

class FileAllInformationSpec extends Specification {
  def "should parse information"() {
    given:
    String hex = "80a79df99105d0013291af48c52dd2013291af48c52dd20136a3af48c52dd201800000000000000000001000000000003e46000000000000010000000000000087006f00010000000000000089001200000000000000000000000000000000002e0000005c006900660073005c006900730069005f006700610074006800650072005f0070006500720066002e0070007900"
    byte[] bytes = ByteArrayUtils.parseHex(hex)

    when:
    def info = FileInformationFactory.getDecoder(FileAllInformation.class).read(new Buffer.PlainBuffer(bytes, Endian.LE))

    then:
    info.basicInformation.creationTime == new FileTime(130610513710000000)
    info.basicInformation.lastAccessTime == new FileTime(131217664498438450)
    info.basicInformation.lastWriteTime == new FileTime(131217664498438450)
    info.basicInformation.changeTime == new FileTime(131217664498443062)
    info.basicInformation.fileAttributes == 128
    info.standardInformation.allocationSize == 1048576
    info.standardInformation.endOfFile == 17982
    info.standardInformation.numberOfLinks == 1
    !info.standardInformation.deletePending
    !info.standardInformation.directory
    info.internalInformation.indexNumber == 4302241927
    info.eaInformation.eaSize == 0
    info.accessInformation.accessFlags == 1179785
    info.positionInformation.currentByteOffset == 0
    info.modeInformation.mode == 0
    info.alignmentInformation.alignmentRequirement == 0
    info.nameInformation == "\\ifs\\isi_gather_perf.py"
  }
}
