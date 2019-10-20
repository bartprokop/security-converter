package com.example.appengine.vertxhello;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.StaticHandler;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Application extends AbstractVerticle {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void start(Future<Void> startFuture) {
        final Router router = Router.router(vertx);
        router.post().handler(BodyHandler.create());
        router.post("/jwk-to-pem").handler(JwkToPem::handle);
        router.post("/pem-to-jwk").handler(PemToJwk::handle);
        router.route().handler(StaticHandler.create("html").setMaxAgeSeconds(60));

        vertx
                .createHttpServer()
                .requestHandler(router)
                .listen(8080, ar -> startFuture.handle(ar.mapEmpty()));
    }

}
