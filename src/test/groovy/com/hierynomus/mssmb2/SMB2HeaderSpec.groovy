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
package com.hierynomus.mssmb2

import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification
import spock.lang.Unroll

class SMB2HeaderSpec extends Specification {

  @Unroll
  def "should write credit request for dialect #dialect"() {
    given:
    def header = new SMB2Header()
    header.setCreditRequest(66)
    header.setCreditCharge(0)
    header.setDialect(dialect)
    header.setMessageType(SMB2MessageCommandCode.SMB2_NEGOTIATE)
    def buffer = new SMBBuffer()

    when:
    header.writeTo(buffer)

    then:
    buffer.rpos(14)
    buffer.readUInt16() == 66

    where:
    dialect << [SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2XX]
  }
}
