package com.cassandra.audit;

import static com.cassandra.audit.Utils.ALLOW_EMPTY_PASS;
import static com.cassandra.audit.Utils.LDAP_BASE_DN;
import static com.cassandra.audit.Utils.LDAP_CASSANDRA_USER_GROUP;
import static com.cassandra.audit.Utils.NUL;
import static com.cassandra.audit.Utils.SYSTEM_USER_CREDENTIALS;
import static com.cassandra.audit.Utils.getLdapConnection;
import static com.unboundid.ldap.sdk.ResultCode.SUCCESS;
import static org.apache.cassandra.auth.PasswordAuthenticator.PASSWORD_KEY;
import static org.apache.cassandra.auth.PasswordAuthenticator.USERNAME_KEY;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;

public class LdapAuthenticator implements IAuthenticator {

    private Cache<String, String> nonSystemUserCache;

    @Override
    public boolean requireAuthentication() {
        return true;
    }

    @Override
    public Set<? extends IResource> protectedResources() {
        return Collections.emptySet();
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
    }

    @Override
    public void setup() {
        nonSystemUserCache = CacheBuilder.newBuilder()
            .expireAfterWrite(DatabaseDescriptor.getCredentialsValidity(), TimeUnit.MILLISECONDS)
            .maximumSize(DatabaseDescriptor.getCredentialsCacheMaxEntries())
            .build();
        if (SYSTEM_USER_CREDENTIALS.isEmpty()) {
            AuditLogger.LOG.warn("System User Credentials is empty, most probably something is wrong.");
        }
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress) {
        return new FreeIPANegotiator();
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        String username = credentials.get(USERNAME_KEY);
        if (username == null) {
            throw new AuthenticationException(String.format("Required key '%s' is missing", USERNAME_KEY));
        }
        String password = credentials.get(PASSWORD_KEY);
        if (password == null && !ALLOW_EMPTY_PASS) {
            throw new AuthenticationException(String.format(
                "Required key '%s' is missing for provided username %s",
                PASSWORD_KEY,
                username
            ));
        }
        return authenticate(username, password);
    }

    private class FreeIPANegotiator implements SaslNegotiator {
        private boolean complete = false;
        private String username;
        private String password;

        @Override
        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        @Override
        public boolean isComplete() {
            return complete;
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (!complete) {
                throw new AuthenticationException("SASL negotiation not complete");
            }
            return authenticate(username, password);
        }

        private void decodeCredentials(byte[] bytes) throws AuthenticationException {
            byte[] user = null;
            byte[] pass = null;
            int end = bytes.length;
            for (int i = bytes.length - 1; i >= 0; i--) {
                if (bytes[i] == NUL) {
                    if (pass == null) {
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    } else if (user == null) {
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    }
                    end = i;
                }
            }
            if (pass == null) {
                throw new AuthenticationException("Password must not be null");
            }
            if (user == null) {
                throw new AuthenticationException("Authentication ID must not be null");
            }
            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
        }
    }

    private AuthenticatedUser authenticate(String username, String password) {
        if (SYSTEM_USER_CREDENTIALS.containsKey(username)) {
            final String systemUserPassword = SYSTEM_USER_CREDENTIALS.get(username);
            if (Objects.equals(systemUserPassword, password)) {
                return new AuthenticatedUser(username);
            } else {
                throw new AuthenticationException(String.format(
                    "Provided system username '%s', the password is incorrect",
                    username
                ));
            }
        }
        String cachedPassword = nonSystemUserCache.getIfPresent(username);
        if (cachedPassword == null) {
            if (ALLOW_EMPTY_PASS) {
                try {
                    final String filterString =
                        String.format(
                            "&(cn=%s)(member=uid=%s,cn=users,cn=accounts,%s)",
                            LDAP_CASSANDRA_USER_GROUP,
                            username,
                            LDAP_BASE_DN
                        );
                    Filter filter =
                        Filter.create(filterString);
                    SearchRequest searchRequest =
                        new SearchRequest(
                            "cn=groups,cn=accounts," + LDAP_BASE_DN,
                            SearchScope.SUB,
                            filter,
                            SearchRequest.NO_ATTRIBUTES
                        );
                    SearchResult result = getLdapConnection().search(searchRequest);
                    if (result.getEntryCount() > 0) {
                        return new AuthenticatedUser(username);
                    } else {
                        throw new AuthenticationException(String.format(
                            "Provided username %s cannot access this Cassandra cluster",
                            username
                        ));
                    }
                } catch (LDAPException e) {
                    AuditLogger.LOG.warn("authenticate get LDAPException: ", e);
                    throw new AuthenticationException(String.format(
                        "Failed to authenticate user %s against FreeIPA",
                        username
                    ) + " , " + e.getMessage());
                }
            } else {
                try {
                    String userDN = "uid=" + username + ",cn=users,cn=accounts," + LDAP_BASE_DN;
                    SimpleBindRequest bindRequest = new SimpleBindRequest(userDN, password);
                    BindResult bindResult = getLdapConnection().bind(bindRequest);
                    if (bindResult.getResultCode() == SUCCESS) {
                        nonSystemUserCache.put(username, password);
                        return new AuthenticatedUser(username);
                    } else {
                        throw new AuthenticationException(String.format(
                            "Provided username %s and/or password are incorrect",
                            username
                        ));
                    }
                } catch (LDAPException e) {
                    AuditLogger.LOG.warn("authenticate get LDAPException: ", e);
                    throw new AuthenticationException(String.format(
                        "Failed to authenticate user %s against FreeIPA",
                        username
                    ) + " , " + e.getMessage());
                }
            }
        }
        if (!Objects.equals(password, cachedPassword)) {
            throw new AuthenticationException(String.format(
                "Provided username %s and/or password are incorrect",
                username
            ));
        }
        return new AuthenticatedUser(username);
    }
}
