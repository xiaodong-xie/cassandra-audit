package com.cassandra.audit;

import static com.cassandra.audit.Utils.READONLY_USERS;
import static com.cassandra.audit.Utils.SYSTEM_USERS;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.cql3.BatchQueryOptions;
import org.apache.cassandra.cql3.CustomPayloadMirroringQueryHandler;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.statements.BatchStatement;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;

public class AuditQueryHandler extends CustomPayloadMirroringQueryHandler {

    @Override
    public ResultMessage process(
        String query,
        QueryState state,
        QueryOptions options,
        Map<String, ByteBuffer> customPayload,
        long queryStartNanoTime
    ) {
        ClientState cs = state.getClientState();
        final InetAddress clientAddress = state.getClientAddress();
        final AuthenticatedUser user = cs.getUser();
        try {
            return super.process(query, state, options, customPayload, queryStartNanoTime);
        } finally {
            final String userName = user.getName();
            if (!SYSTEM_USERS.contains(userName) && !READONLY_USERS.contains(userName)) {
                AuditLogger.prepareAuditLog(userName, clientAddress, query, queryStartNanoTime);
            }
        }
    }

    @Override
    public ResultMessage processBatch(
        BatchStatement statement,
        QueryState state,
        BatchQueryOptions options,
        Map<String, ByteBuffer> customPayload,
        long queryStartNanoTime
    ) {
        ClientState cs = state.getClientState();
        final InetAddress clientAddress = state.getClientAddress();
        final AuthenticatedUser user = cs.getUser();
        try {
            return super.processBatch(statement, state, options, customPayload, queryStartNanoTime);
        } finally {
            final String userName = user.getName();
            if (!SYSTEM_USERS.contains(userName) && !READONLY_USERS.contains(userName)) {
                AuditLogger.prepareAuditLog(userName, clientAddress, statement.toString(), queryStartNanoTime);
            }
        }
    }

    @Override
    public ResultMessage.Prepared prepare(String query, QueryState state, Map<String, ByteBuffer> customPayload) {
        ClientState cs = state.getClientState();
        final InetAddress clientAddress = state.getClientAddress();
        final AuthenticatedUser user = cs.getUser();
        try {
            return super.prepare(query, state, customPayload);
        } finally {
            final String userName = user.getName();
            if (!SYSTEM_USERS.contains(userName) && !READONLY_USERS.contains(userName)) {
                AuditLogger.prepareAuditLog(userName, clientAddress, query);
            }
        }
    }
}
