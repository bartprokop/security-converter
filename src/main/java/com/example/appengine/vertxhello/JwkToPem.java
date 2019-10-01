/*
 * Copyright 2019 Bart Prokop
 *
 */
package com.example.appengine.vertxhello;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 *
 * @author Bart Prokop
 */
public class JwkToPem {

    private final static Base64.Encoder ENCODER = Base64.getMimeEncoder();
    private final static Base64.Decoder DECODER = Base64.getUrlDecoder();

    public static PublicKey fromJwk(JsonObject jwk) throws GeneralSecurityException {
        final String kty = jwk.getString("kty");
        final String n = jwk.getString("n");
        final String e = jwk.getString("e");

        final BigInteger N = new BigInteger(1, DECODER.decode(n));
        final BigInteger E = new BigInteger(1, DECODER.decode(e));

        final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(N, E);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    public static String toPem(PublicKey publicKey) {
        byte[] der = publicKey.getEncoded();
        StringBuilder pem = new StringBuilder();

        pem.append("-----BEGIN PUBLIC KEY-----").append('\n');
        pem.append(ENCODER.encodeToString(der));
        pem.append('\n').append("-----END PUBLIC KEY-----");

        return pem.toString();
    }

    public static void handle(RoutingContext routingContext) {
        routingContext.request().bodyHandler(buffer -> {
            try {
                JsonObject body = new JsonObject(buffer);
                PublicKey fromJwk = fromJwk(body);
                String toPem = toPem(fromJwk);
                System.out.println(toPem);
                routingContext.response().end(toPem);
            } catch (Exception e) {
                routingContext.fail(e);
            }
        });
    }

}
