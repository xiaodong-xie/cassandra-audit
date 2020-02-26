package com.cassandra.audit;

import static com.cassandra.audit.Utils.LDAP_BASE_DN;
import static com.cassandra.audit.Utils.READONLY_USERS;
import static com.cassandra.audit.Utils.SYSTEM_USERS;
import static com.cassandra.audit.Utils.getLdapConnection;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableSet;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.IRoleManager;
import org.apache.cassandra.auth.RoleOptions;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;

public class LdapRoleManager implements IRoleManager {

    private static final Object DUMMY = new Object();

    private final Set<Option> supportedOptions = ImmutableSet.of(Option.LOGIN, Option.SUPERUSER);
    private final Set<Option> alterableOptions = ImmutableSet.of();
    private Cache<String, Object> nonSystemUserCache;

    @Override
    public Set<Option> supportedOptions() {
        return supportedOptions;
    }

    @Override
    public Set<Option> alterableOptions() {
        return alterableOptions;
    }

    @Override
    public void createRole(
        AuthenticatedUser performer, RoleResource role, RoleOptions options
    ) throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("createRole called, please go for LDAP server directly.");
    }

    @Override
    public void dropRole(AuthenticatedUser performer, RoleResource role)
        throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("dropRole called, please go for LDAP server directly.");
    }

    @Override
    public void alterRole(AuthenticatedUser performer, RoleResource role, RoleOptions options)
        throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("alterRole called, please go for LDAP server directly.");
    }

    @Override
    public void grantRole(AuthenticatedUser performer, RoleResource role, RoleResource grantee)
        throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("grantRole called, please go for LDAP server directly.");
    }

    @Override
    public void revokeRole(AuthenticatedUser performer, RoleResource role, RoleResource revokee)
        throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("revokeRole called, please go for LDAP server directly.");
    }

    @Override
    public Set<RoleResource> getRoles(RoleResource grantee, boolean includeInherited)
        throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("getRoles called, please go for LDAP server directly.");
        return Collections.emptySet();
    }

    @Override
    public Set<RoleResource> getAllRoles() throws RequestValidationException, RequestExecutionException {
        AuditLogger.LOG.info("getAllRoles called, please go for LDAP server directly.");
        return Collections.emptySet();
    }

    @Override
    public boolean isSuper(RoleResource role) {
        if (READONLY_USERS.contains(role.getRoleName())) {
            return false;
        }
        return userExistsWithCache(role);
    }

    @Override
    public boolean canLogin(RoleResource role) {
        if (READONLY_USERS.contains(role.getRoleName())) {
            return true;
        }
        return userExistsWithCache(role);
    }

    @Override
    public Map<String, String> getCustomOptions(RoleResource role) {
        return Collections.emptyMap();
    }

    @Override
    public boolean isExistingRole(RoleResource role) {
        if (READONLY_USERS.contains(role.getRoleName())) {
            return true;
        }
        return userExistsWithCache(role);
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
    }

    private boolean userExistsWithCache(RoleResource role) {
        if (SYSTEM_USERS.contains(role.getRoleName())) {
            return true;
        }
        if (nonSystemUserCache.getIfPresent(role.getRoleName()) != null) {
            return true;
        }
        return userExists(role.getRoleName());
    }

    private boolean userExists(String username) {
        try {
            Filter filter = Filter.create(String.format("(uid=%s)", username));
            final String baseDN = "cn=users,cn=accounts," + LDAP_BASE_DN;
            SearchRequest searchRequest =
                new SearchRequest(
                    baseDN,
                    SearchScope.SUB,
                    filter,
                    SearchRequest.NO_ATTRIBUTES
                );
            SearchResult result = getLdapConnection().search(searchRequest);
            boolean exist = result.getEntryCount() >= 1;
            if (exist) {
                nonSystemUserCache.put(username, DUMMY);
            }
            return exist;
        } catch (LDAPException e) {
            AuditLogger.LOG.warn("Got LDAPException when checking user {} existence. ", username, e);
            return false;
        }
    }
}
