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
package com.hierynomus.smbj.testing;

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;

public class Utils {
    public static SmbConfig config(PacketProcessor processor) {
        return configBuilder(processor).build();
    }

    public static SmbConfig.Builder configBuilder(PacketProcessor processor) {
        return SmbConfig.builder()
                .withTransportLayerFactory(new StubTransportLayerFactory<>(new DefaultPacketProcessor().wrap(processor)))
                .withAuthenticators(new StubAuthenticator.Factory());
    }
}
