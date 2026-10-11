package com.guardcore.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.guardcore.config.SecurityConfig;
import com.guardcore.config.SecurityConfigBuilder;
import com.guardcore.core.TestRequest;
import com.guardcore.core.TestMiddleware;
import com.guardcore.core.checks.ChecksFactory;
import com.guardcore.core.checks.SecurityCheckPipeline;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The Java-side consumer proof for the bridge convention: the same engine entry points called from
 * Java source through the {@code CompletableFuture} and blocking statics, no Kotlin source
 * coupling.
 */
public class JavaBridgeConsumerTest {
  private static SecurityConfig config() {
    return new SecurityConfigBuilder().build();
  }

  @Test
  public void pipelineRunsFromJavaThroughBothBridgeShapes() throws Exception {
    TestMiddleware middleware = new TestMiddleware(config(), null, null);
    SecurityCheckPipeline pipeline = ChecksFactory.INSTANCE.buildDefaultPipeline(middleware);
    TestRequest request = new TestRequest("192.0.2.10", "/health", "http", Map.of(), new byte[0], "GET");

    CompletableFuture<?> future = JavaBridges.executePipeline(pipeline, request);
    Object viaFuture = future.get(30, TimeUnit.SECONDS);
    Object viaBlocking = JavaBridges.executePipelineBlocking(pipeline, request);
    assertTrue(future.isDone());
    if (viaFuture == null) {
      assertEquals(null, viaBlocking);
    } else {
      assertEquals(
          ((com.guardcore.protocols.GuardResponse) viaFuture).getStatusCode(),
          ((com.guardcore.protocols.GuardResponse) viaBlocking).getStatusCode());
    }
  }

  @Test
  public void detectRunsFromJava() throws Exception {
    var verdict =
        JavaBridges.detect("<script>alert(1)</script>", "203.0.113.7", "body").get(30, TimeUnit.SECONDS);
    assertTrue(verdict.isThreat());
    assertTrue(JavaBridges.detectBlocking("<script>alert(1)</script>", "203.0.113.7", "body").isThreat());
  }

  @Test
  public void testRequestDefaultsStayAccessible() {
    // The support-class smoke: Java consumers can build the harness request type.
    TestRequest request = new TestRequest("192.0.2.10", "/api", "http", Map.of(), new byte[0], "GET");
    assertEquals("/api", request.getUrlPath());
    assertEquals("http", request.getUrlScheme());
  }
}
