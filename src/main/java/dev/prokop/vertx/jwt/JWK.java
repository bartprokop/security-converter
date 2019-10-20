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

import io.vertx.core.json.JsonObject;
import java.security.Key;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 *
 * @author Bart Prokop
 */
public class JWK {

    private final Key key;
    private final JsonObject jwk = new JsonObject();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    public JWK(Key key) {
        this.key = key;
        parse();
    }

    private void parse() {
        if (key instanceof RSAPublicKey) {
            RSAPublicKey key = (RSAPublicKey) this.key;
            jwk.put("kty", "RSA");
            jwk.put("n", URL_ENCODER.encodeToString(trim(key.getModulus().toByteArray())));
            jwk.put("e", URL_ENCODER.encodeToString(trim(key.getPublicExponent().toByteArray())));
        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) this.key;
            jwk.put("kty", "RSA");
            // The "n" (modulus) parameter contains the modulus value for the RSA public key
            jwk.put("n", URL_ENCODER.encodeToString(trim(key.getModulus().toByteArray())));
            // The "e" (exponent) parameter contains the exponent value for the RSA public key
            jwk.put("e", URL_ENCODER.encodeToString(trim(key.getPublicExponent().toByteArray())));
            // The "d" (private exponent) parameter contains the private exponent value for the RSA private key
            jwk.put("d", URL_ENCODER.encodeToString(trim(key.getPrivateExponent().toByteArray())));
            // The "p" (first prime factor) parameter contains the first prime factor
            jwk.put("p", URL_ENCODER.encodeToString(trim(key.getPrimeP().toByteArray())));
            // The "q" (second prime factor) parameter contains the second prime factor
            jwk.put("q", URL_ENCODER.encodeToString(trim(key.getPrimeQ().toByteArray())));
            // The "dp" (first factor CRT exponent) parameter contains the Chinese Remainder Theorem (CRT) exponent of the first factor
            jwk.put("dp", URL_ENCODER.encodeToString(trim(key.getPrimeExponentP().toByteArray())));
            // The "dq" (second factor CRT exponent) parameter contains the CRT exponent of the second factor
            jwk.put("dq", URL_ENCODER.encodeToString(trim(key.getPrimeExponentQ().toByteArray())));
            // The "qi" (first CRT coefficient) parameter contains the CRT coefficient of the second factor
            jwk.put("qi", URL_ENCODER.encodeToString(trim(key.getCrtCoefficient().toByteArray())));
        } else {
            throw new IllegalArgumentException("Unknown Key Type");
        }
    }

    private static byte[] trim(byte[] bytes) {
        while (bytes.length > 0 && bytes[0] == 0) {
            byte[] smaller = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, smaller, 0, bytes.length - 1);
            bytes = smaller;
        }
        return bytes;
    }

    public Key getKey() {
        return key;
    }

    public JsonObject getJwk() {
        return jwk;
    }

}
