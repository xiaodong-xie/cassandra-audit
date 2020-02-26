package com.cassandra.audit;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AuditLogger {
    public static final Logger LOG = LoggerFactory.getLogger(AuditLogger.class);
    public static final List<String> WHITE_LISTED_TABLES = new ArrayList<>();

    static {
        WHITE_LISTED_TABLES.add("from system_schema.");
        WHITE_LISTED_TABLES.add("from system.");
    }

    public static void prepareAuditLog(
        String userName,
        InetAddress userInetAddress,
        String query,
        long queryStartNanoTime
    ) {
        boolean whiteListed = WHITE_LISTED_TABLES.stream().anyMatch(s -> query.toLowerCase().contains(s));
        if (!whiteListed) {
            LOG.info("AuditLog: {} at {} executed query {} query took {} millis", userName, userInetAddress, query,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - queryStartNanoTime)
            );
        }
    }

    public static void prepareAuditLog(String userName, InetAddress userInetAddress, String query) {
        boolean whiteListed = WHITE_LISTED_TABLES.stream().anyMatch(s -> query.toLowerCase().contains(s));
        if (!whiteListed) {
            LOG.info("AuditLog: {} at {} prepared query {}", userName, userInetAddress, query);
        }
    }
}
