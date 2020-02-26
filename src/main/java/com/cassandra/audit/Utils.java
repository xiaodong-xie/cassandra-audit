package com.cassandra.audit;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.ssl.SSLUtil;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.net.ssl.SSLSocketFactory;

public final class Utils {
    private static final String LDAP_SYS_USERNAME_SSM_NAME_KEY = "ldap-sys-username";
    private static final String LDAP_SYS_USER_PWD_SSM_NAME_KEY = "ldap-sys-userpass";

    static final List<String> SYSTEM_USERS = new ArrayList<>();
    static final ConcurrentMap<String, String> SYSTEM_USER_CREDENTIALS = new ConcurrentHashMap<>();
    static final List<String> READONLY_USERS = new ArrayList<>();
    static final ConcurrentMap<String, String> READONLY_USER_CREDENTIALS = new ConcurrentHashMap<>();
    static final String LDAP_SERVER_ADDR;
    static final String LDAP_SERVER_PORT;
    static final String LDAP_BASE_DN;
    static final String LDAP_SYS_USERNAME;
    static final String LDAP_SYS_USER_PWD;
    static final String LDAP_CASSANDRA_USER_GROUP;
    static final boolean ALLOW_EMPTY_PASS;
    static final byte NUL = 0;
    private static LDAPConnection ldapConnection;

    static {
        LDAP_SERVER_ADDR = System.getProperty("ldap-server-addr");
        LDAP_SERVER_PORT = System.getProperty("ldap-server-port", "636");
        LDAP_BASE_DN = System.getProperty("ldap-base-dn");
        ALLOW_EMPTY_PASS = Boolean.parseBoolean(System.getProperty("allow-empty-pass", "false"));
        LDAP_CASSANDRA_USER_GROUP = System.getProperty("ldap-cassandra-user-group");
        String ldapSysUserNameKey = System.getProperty(LDAP_SYS_USERNAME_SSM_NAME_KEY, LDAP_SYS_USERNAME_SSM_NAME_KEY);
        String ldapSysUserPassKey = System.getProperty(LDAP_SYS_USER_PWD_SSM_NAME_KEY, LDAP_SYS_USER_PWD_SSM_NAME_KEY);
        String cassandraSystemUsername = System.getProperty("cassandra-system-username");
        String cassandraSystemUserPass = System.getProperty("cassandra-system-userpass");
        String cassandraReadOnlyUsername = System.getProperty("cassandra-readonly-username");
        String cassandraReadOnlyUserPass = System.getProperty("cassandra-readonly-userpass");
        AWSSimpleSystemsManagement ssmClient = null;
        try {
            ssmClient = AWSSimpleSystemsManagementClientBuilder.standard().withRegion(Regions.EU_WEST_1).build();
            LDAP_SYS_USERNAME = getFromAwsSSM(ssmClient, ldapSysUserNameKey);
            LDAP_SYS_USER_PWD = getFromAwsSSM(ssmClient, ldapSysUserPassKey);
            String systemUserName = getFromAwsSSM(ssmClient, cassandraSystemUsername);
            SYSTEM_USERS.add(systemUserName);
            String readOnlyUserName = getFromAwsSSM(ssmClient, cassandraReadOnlyUsername);
            READONLY_USERS.add(readOnlyUserName);
            String systemUserPassword = getFromAwsSSM(ssmClient, cassandraSystemUserPass);
            SYSTEM_USER_CREDENTIALS.put(systemUserName, systemUserPassword);
            String readOnlyUserPassword = getFromAwsSSM(ssmClient, cassandraReadOnlyUserPass);
            READONLY_USER_CREDENTIALS.put(readOnlyUserName, readOnlyUserPassword);
        } finally {
            if (ssmClient != null) {
                ssmClient.shutdown();
            }
        }
        try {
            // user this if having any issues with certificates.
            // SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
            SSLUtil sslUtil = new SSLUtil();
            SSLSocketFactory socketFactory = sslUtil.createSSLSocketFactory();
            String bindDN = "uid=" + LDAP_SYS_USERNAME + ",cn=users,cn=accounts," + LDAP_BASE_DN;
            ldapConnection = new LDAPConnection(
                socketFactory,
                LDAP_SERVER_ADDR,
                Integer.parseInt(LDAP_SERVER_PORT),
                bindDN,
                LDAP_SYS_USER_PWD
            );
        } catch (GeneralSecurityException | LDAPException e) {
            AuditLogger.LOG.warn("Failed to initialize. ", e);
        }
    }

    private static String getFromAwsSSM(AWSSimpleSystemsManagement ssmClient, String name) {
        final GetParameterResult parameter =
            ssmClient.getParameter(new GetParameterRequest().withName(name).withWithDecryption(true));
        return parameter.getParameter().getValue();
    }

    protected static LDAPConnection getLdapConnection() {
        if (ldapConnection != null) {
            return ldapConnection;
        }
        throw new IllegalStateException("Failed to initialize ldapConnection.");
    }
}
