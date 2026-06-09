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
package com.hierynomus.smbfs;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ShareSourceImplTest {

    @Mock
    private SMBClient smbClient;

    @Test
    void closeShutsDownClient() throws Exception {
        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        source.close();

        verify(smbClient).close();
    }

    @Test
    void rejectsOpenAfterClose() throws Exception {
        ShareSourceImpl source = new ShareSourceImpl(smbClient, "host", 445, AuthenticationContext.anonymous());

        source.close();

        assertThrows(IllegalStateException.class, () -> source.open("share"));
    }
}
