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
package com.hierynomus.smbj;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

import com.hierynomus.mssmb2.SMB2Dialect;

public class SmbConfigTest {
    @Test
    public void testCreateDefaultConfig() {
        assertDoesNotThrow(() -> SmbConfig.createDefaultConfig());
    }

    @Test
    public void shouldNotBuildConfigWithRequiredAndDisabledSigning() {
        assertThrows(IllegalStateException.class,
                () -> SmbConfig.builder().withDialects(SMB2Dialect.SMB_2_0_2).withSigningRequired(true).withSigningEnabled(false).build());
    }

    @Test
    public void shouldNotBuildConfigWithDisabledSigningAndSmb3xDialect() {
        assertThrows(IllegalStateException.class,
                () -> SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_0).withSigningEnabled(false).build());
    }
}
