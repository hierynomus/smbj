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
package com.hierynomus.msdtyp

import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class MsDataTypesSpec extends Specification {

  def "should read/write UUID correctly"() {
    given:
    def buffer = new SMBBuffer()
    def uuid = UUID.fromString("fbbd1895-af40-48a4-a183-8dabeb1e901a")

    when:
    MsDataTypes.putGuid(uuid, buffer)

    then:
    buffer.printHex() == "95 18 bd fb 40 af a4 48 a1 83 8d ab eb 1e 90 1a"
    MsDataTypes.readGuid(buffer) == uuid
  }
}
