/*
 * Copyright 2019 Bart Prokop
 *
 */
package com.example.appengine.vertxhello;

import dev.prokop.vertx.jwt.JWK;
import dev.prokop.vertx.jwt.SecurityToolbox;
import io.vertx.ext.web.RoutingContext;
import java.security.Key;

/**
 *
 * @author Bart Prokop
 */
public class PemToJwk {

    public static void handle(RoutingContext routingContext) {
        try {
            String body = routingContext.getBodyAsString();
            System.out.println(body);
            System.out.println(body.length());
            Key pem = SecurityToolbox.pem(body);
            JWK jwk = new JWK(pem);
            routingContext.response().end(jwk.getJwk().encodePrettily());
        } catch (Exception e) {
            e.printStackTrace();
            routingContext.response().end(exceptionToString(e));
        }
    }

    public static String exceptionToString(final Exception exception) {
        final StringBuilder retVal = new StringBuilder();
        retVal.append(exception.toString()); // do better in future
        return retVal.toString();
    }

}
