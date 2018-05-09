package com.cassandra.audit;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AuditLogger {
    public static final Logger LOG = LoggerFactory.getLogger(AuditLogger.class);

    public static void auditLog(String userName, InetAddress userInetAddress, String query, long queryStartNanoTime) {
        LOG.info("AuditLog: {} at {} executed query {} query took {} millis", userName, userInetAddress, query,
            TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - queryStartNanoTime)
        );
    }
}
