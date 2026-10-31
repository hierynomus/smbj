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
package com.hierynomus.smbj.common;

import com.hierynomus.protocol.transport.TransportException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.SocketException;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(5)
public class SMBSecurityExceptionTest {
    @Test
    public void shouldFindFirstSecurityExceptionIncludingItself() {
        SMBSecurityException inner = new SMBSecurityException("Inner failure");
        SMBSecurityException outer = new SMBSecurityException("Outer failure", inner);

        assertEquals("Outer failure", outer.getMessage());
        assertSame(inner, outer.getCause());
        assertSame(inner, SMBSecurityException.find(inner));
        assertSame(outer, SMBSecurityException.find(outer));
        assertSame(outer, SMBSecurityException.find(new SMBRuntimeException(new ExecutionException(outer))));
    }

    @Test
    public void shouldReturnNullForOrdinaryTransportFailureAndNull() {
        TransportException failure = new TransportException(new SocketException("Socket closed"));

        assertNull(SMBSecurityException.find(failure));
        assertNull(SMBSecurityException.find(new SMBRuntimeException(failure)));
        assertNull(SMBSecurityException.find(null));
    }

    @Test
    public void shouldReturnNullForCauseCycle() {
        Throwable first = new Exception("First");
        Throwable second = new Exception("Second", first);
        first.initCause(second);

        assertNull(SMBSecurityException.find(first));
        assertNull(SMBSecurityException.find(second));
    }
}
