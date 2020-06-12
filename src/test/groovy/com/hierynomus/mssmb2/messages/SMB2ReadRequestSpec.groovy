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
package com.hierynomus.mssmb2.messages

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification
import spock.lang.Unroll

class SMB2ReadRequestSpec extends Specification {
  @Unroll
  def "should always read the exact bytes range the user request to avoid possible byte range lock issue (offset #offset, maxPayloadSize #maxPayloadSize)"() {
    given:
    byte[] expectedData = ByteArrayUtils.parseHex(expectedResult)

    String givenFileIdString = "03270700350000000500000035000000"
    byte[] givenFileIdBytes = ByteArrayUtils.parseHex(givenFileIdString)
    byte[] givenPersistentFileIdBytes = Arrays.copyOfRange(givenFileIdBytes, 0, 8)
    byte[] givenVolatileFileIdBytes = Arrays.copyOfRange(givenFileIdBytes, 8, 16)

    SMB2Dialect dialect = SMB2Dialect.SMB_2_1;
    SMB2FileId fileId = new SMB2FileId(givenPersistentFileIdBytes, givenVolatileFileIdBytes)
    long sessionId = 0x0000d40e0c000301
    long treeId = 1L
    long messageId = 6L


    when:
    SMB2ReadRequest smb2ReadRequest = new SMB2ReadRequest(dialect, fileId, sessionId, treeId, offset, maxPayloadSize)
    smb2ReadRequest.getHeader().setMessageId(messageId)
    SMBBuffer outputBuffer = new SMBBuffer()
    smb2ReadRequest.write(outputBuffer)
    byte[] outputData = outputBuffer.getCompactData()
    byte[] extractedOutputData = Arrays.copyOfRange(outputData, 64, outputData.length)
    byte[] extractedExpectedData = Arrays.copyOfRange(expectedData, 64, outputData.length)

    then:
    // the read request should be the same
    Arrays.equals(extractedExpectedData, extractedOutputData)
    // the whole request including header should be the same
    Arrays.equals(expectedData, outputData)

    where:
    offset | maxPayloadSize | expectedResult
    0L     | 15             | "fe534d424000010000000000080001000000000000000000060000000000000000000000010000000103000c0ed4000000000000000000000000000000000000310000000f0000000000000000000000032707003500000005000000350000000100000000000000000000000000000000"
//    0L     | 131071         | "fe534d424000010000000000080001000000000000000000060000000000000000000000010000000103000c0ed400000000000000000000000000000000000031000000ffff01000000000000000000032707003500000005000000350000000100000000000000000000000000000000"‬

  }
}
