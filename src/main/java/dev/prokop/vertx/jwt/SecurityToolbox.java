/*
 * Copyright 2019 proko.
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

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.PEMUtil;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 *
 * @author Bart Prokop
 */
public class SecurityToolbox {

    private final static Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder();
    private final static Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();

    public static String pem(Key publicKey) {
        byte[] der = publicKey.getEncoded();
        StringBuilder pem = new StringBuilder();

        pem.append("-----BEGIN PUBLIC KEY-----").append('\n');
        pem.append(MIME_ENCODER.encodeToString(der));
        pem.append('\n').append("-----END PUBLIC KEY-----");

        return pem.toString();
    }

    public static Key pem(String key) {
        try {
            System.out.println(key);
            StringReader keyReader = new StringReader(key);
            PemReader pemReader = new PemReader(keyReader);
            PemObject readPemObject = pemReader.readPemObject();
            EncodedKeySpec spec = new PKCS8EncodedKeySpec(readPemObject.getContent(), "RSA");
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            return kf.generatePrivate(spec);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

}
