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

class SMB2ErrorSpec extends Specification {

  def "ErrorData - Empty"() {
    given:
    def header = new SMB2Header()
    def buffer = new SMBBuffer()
    buffer.putReserved(2)
    buffer.putReserved(1)
    buffer.putReserved(1)
    buffer.putUInt32(0L)
    buffer.putReserved(1)

    when:
    def error = new SMB2Error()
    error.read(header, buffer)

    then:
    error.getErrorData().size() == 0
  }

  def "ErrorData - Empty - W10 1709"() {
    given:
    def header = new SMB2Header()
    def buffer = new SMBBuffer()
    buffer.putReserved(2)
    buffer.putReserved(1)
    buffer.putReserved(1)
    buffer.putUInt32(0L)
    // No ErrorData reserved byte provided

    when:
    def error = new SMB2Error()
    error.read(header, buffer)

    then:
    error.getErrorData().size() == 0
  }
}
