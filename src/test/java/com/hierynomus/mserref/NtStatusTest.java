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

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class NtStatusTest {
    @ParameterizedTest(name = "{0} should have STATUS_SEVERITY_SUCCESS status")
    @EnumSource(value = NtStatus.class, names = {"STATUS_SUCCESS", "STATUS_PENDING"})
    public void shouldHaveSuccessStatus(NtStatus s) {
        assertTrue(s.isSuccess());
    }

    @ParameterizedTest(name = "{0} should have STATUS_SEVERITY_ERROR status")
    @EnumSource(value = NtStatus.class, names = {"STATUS_ACCESS_DENIED", "STATUS_END_OF_FILE"})
    public void shouldHaveErrorStatus(NtStatus s) {
        assertTrue(s.isError());
    }
}
