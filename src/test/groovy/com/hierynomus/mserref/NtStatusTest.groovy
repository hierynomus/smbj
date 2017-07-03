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
package com.hierynomus.mserref

import spock.lang.Specification
import spock.lang.Unroll

@Unroll
class NtStatusTest extends Specification {

  def "#ntStatus should be STATUS_SEVERITY_SUCCESS status code"() {
    expect:
    ntStatus.isSuccess()

    where:
    ntStatus << [NtStatus.STATUS_SUCCESS, NtStatus.STATUS_PENDING]
  }

  def "#ntStatus should be STATUS_SEVERITY_ERROR status code"() {
    expect:
    ntStatus.isError()

    where:
    ntStatus << [NtStatus.STATUS_ACCESS_DENIED, NtStatus.STATUS_END_OF_FILE]
  }
}
