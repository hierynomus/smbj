package com.hierynomus.smbj.testing;

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;

public class Utils {
    public static SmbConfig config(PacketProcessor processor) {
        return SmbConfig.builder()
                .withTransportLayerFactory(new StubTransportLayerFactory<>(new DefaultPacketProcessor().wrap(processor)))
                .withAuthenticators(new StubAuthenticator.Factory()).build();
    }
}
