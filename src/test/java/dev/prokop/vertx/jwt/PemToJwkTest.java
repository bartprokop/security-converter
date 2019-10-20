/*
 * Copyright 2019 Bart Prokop
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.prokop.vertx.jwt;

import io.vertx.core.buffer.Buffer;
import java.io.InputStream;
import java.security.Key;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Bart Prokop
 */
public class PemToJwkTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void test() throws Exception {
        InputStream resourceAsStream = SecurityToolbox.class.getResourceAsStream("/html/pem-to-jwk.pem");
        byte[] arr = resourceAsStream.readAllBytes();
        String pem = Buffer.buffer(arr).toString();
        System.out.println(pem);

        Key key = SecurityToolbox.pem(pem);
        JWK jwk = new JWK(key);
        Assert.assertEquals("RSA", jwk.getJwk().getString("kty"));
        Assert.assertEquals("gRtjwICtIC_4ae33Ks7S80n32PLFEC4UtBanBFE9Pjzcpp4XWDPgbbOkNC9BZ-Jkyq6aoP_UknfJPI-cIvE6IE96bPNGs6DcfZ73Cq2A9ZXTdiuuOiqMwhEgLKFVRUZZ50calENLGyi96-6lcDnwLehh-kEg7ARITmrBO0iAjFU", jwk.getJwk().getString("n"));
        Assert.assertEquals("AQAB", jwk.getJwk().getString("e"));
        Assert.assertEquals("WfQZdmCxP0HtFPFGSz87X2NkGnZbs0BIEInP6IQp5ZlGK5jurvfGIOkPOYTLT3Q_wbAR8KcPFtX7EgUFRptIYYZ_UDt-w0rGc0j7QJYrr3ZLLapYE8jtxW8_E8j3Q4MIGUbh_fZe-12PGNvH_GX7i-hyfrl8zmPD4uE3qfo96Gk", jwk.getJwk().getString("d"));
        Assert.assertEquals("04YyuClFD09BxBu7S8r30ptjAA3hPsMp3dKZYP70rvkeBQb9LfPpEP44CYq5YDuKHUQBqfQcVQNsWWab7Pox5w", jwk.getJwk().getString("p"));
        Assert.assertEquals("nEDirTjo_iY7gq_uGjpFYQZVxBxqobTzHpcO6tVgOGhaZDOFAZnKRStdrLL44gaeDXBM3cBOMhwnjCdfiN7AYw", jwk.getJwk().getString("q"));
        Assert.assertEquals("yr0ime88eQsPTwcBgwjcdalnv2KOVRi8ZRd42UYlghvWER18x3G0Hwx663JicYE_xQMs0RffnAA29o1pwD6iWw", jwk.getJwk().getString("dp"));
        Assert.assertEquals("AnNyGs19uh7XaCFiVr77P55d0gmwEoFIHv63mS9npvrcEB5Ow8upxJP9kCvug30fFY7hZckScO7IIAauFPOJiQ", jwk.getJwk().getString("dq"));
        Assert.assertEquals("gDGal7lIcXOIUJKybNCwQqaEIoN6ihc3mnC48mpov8YHyqabOZ6d-4AkMXBnqi331JFnbKbkhzZ3TsWWsBzTRA", jwk.getJwk().getString("qi"));
    }

}
