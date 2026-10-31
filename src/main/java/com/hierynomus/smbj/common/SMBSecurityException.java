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

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * Thrown when a final SESSION_SETUP response lacks a required signature or signing key,
 * has an invalid signature, or returns an unrequested null session while signing is required.
 * Guest sessions rejected because signing is required use
 * {@link com.hierynomus.smbj.session.SMB2GuestSigningRequiredException} instead.
 * Also thrown when a final response to an encrypted request is unencrypted or has a different
 * session ID from the request, or a decrypted response member has a different session ID from
 * its transform header. These encryption violations abort the connection and fail all its
 * outstanding requests with this exception, possibly wrapped in another exception.
 * <p>
 * Per-member signature and correlation failures (invalid signatures, unknown sessions,
 * uncorrelated responses, or wrong commands or sessions) that [MS-SMB2] requires to be
 * silently discarded do not throw this exception.
 */
@SuppressWarnings("serial")
public class SMBSecurityException extends TransportException {
    /**
     * Creates a protection failure with the given message.
     * @param message the description of the failure
     */
    public SMBSecurityException(String message) {
        super(message);
    }

    /**
     * Creates a protection failure with the given message and cause.
     * @param message the description of the failure
     * @param cause the underlying cause
     */
    public SMBSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Finds the first protection failure in a cause chain, including the supplied throwable.
     * Cause cycles are visited only once.
     * @param t the throwable to inspect, or {@code null}
     * @return the first {@code SMBSecurityException}, or {@code null} if none is present
     */
    public static SMBSecurityException find(Throwable t) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        while (t != null && seen.add(t)) {
            if (t instanceof SMBSecurityException) {
                return (SMBSecurityException) t;
            }
            t = t.getCause();
        }
        return null;
    }
}
