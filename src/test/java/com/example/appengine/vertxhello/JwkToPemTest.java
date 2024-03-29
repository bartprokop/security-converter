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
package com.example.appengine.vertxhello;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import java.io.InputStream;
import java.security.PublicKey;
import org.junit.Test;

/**
 *
 * @author Bart Prokop
 */
public class JwkToPemTest {

    @Test
    public void test() throws Exception {
        InputStream resourceAsStream = JwkToPem.class.getResourceAsStream("/html/jwk-to-pem.json");
        byte[] arr = new byte[resourceAsStream.available()];
        resourceAsStream.read(arr);
        JsonObject jsonObject = new JsonObject(Buffer.buffer(arr));
        System.out.println(jsonObject);
        
        PublicKey fromJwk = JwkToPem.fromJwk(jsonObject);
        System.out.println(fromJwk);
    }

}
