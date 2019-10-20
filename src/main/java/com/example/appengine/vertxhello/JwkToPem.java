/*
 * Copyright 2019 Bart Prokop
 *
 */
package com.example.appengine.vertxhello;

import static dev.prokop.vertx.jwt.SecurityToolbox.pem;
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

    public static void handle(RoutingContext routingContext) {
        try {
            JsonObject body = routingContext.getBodyAsJson();
            PublicKey fromJwk = fromJwk(body);
            String toPem = pem(fromJwk);
            routingContext.response().end(toPem);
        } catch (Exception e) {
//                routingContext.fail(e);
            routingContext.response().end(exceptionToString(e));
        }
    }

    public static String exceptionToString(final Exception exception) {
        final StringBuilder retVal = new StringBuilder();
        retVal.append(exception.toString()); // do better in future
        return retVal.toString();
    }

}
