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
package com.hierynomus.smbj.event;

import net.engio.mbassy.bus.SyncMessageBus;
import net.engio.mbassy.bus.common.PubSubSupport;
import net.engio.mbassy.bus.error.IPublicationErrorHandler;
import net.engio.mbassy.bus.error.PublicationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Our own delegating class to wrap the MBassador event bus. This ensures that we only need to use their annotations
 * throughout the codebase, and can easily switch it out if need be.
 */
public class SMBEventBus {
    private static final Logger log = LoggerFactory.getLogger(SMBEventBus.class);

    private PubSubSupport<SMBEvent> wrappedBus;

    public SMBEventBus() {
        this(new SyncMessageBus<SMBEvent>(new IPublicationErrorHandler() {
            @Override
            public void handleError(PublicationError error) {
                if (error.getCause() != null) {
                    log.error(error.toString(), error.getCause());
                } else {
                    log.error(error.toString());
                }
            }
        }));
    }

    public SMBEventBus(PubSubSupport<SMBEvent> wrappedBus) {
        this.wrappedBus = wrappedBus;
    }

    public void subscribe(Object listener) {
        wrappedBus.subscribe(listener);
    }

    public boolean unsubscribe(Object listener) {
        return wrappedBus.unsubscribe(listener);
    }

    public void publish(SMBEvent message) {
        wrappedBus.publish(message);
    }
}
