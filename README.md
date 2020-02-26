# Cassandra Audit Proof of Concept

Cassandra does not include auditing feature in the open-source version. Here is a proof of concept for achieving query logs and authentication/authorization based on an existing LDAP server. 

By the way, the DataStax enterprise version of Cassandra has far more excellent features other than auditing. Go for that if possible. 

## Background
* This library mainly assumes you are using an LDAP server for authentication.
* This library support both scenarios, users having password (e.g. your prod environment), or users with no password (e.g. your test environment)
* It separate system users (users that will be used by different micro-services), readonly users (for any readonly purposes) and admin users (developers or DBA that would query Cassandra with CQLSH). It will not log queries for system/readonly users, otherwise the log files would be really huge.
* It assumes that the system user credentials are stored in [`AWS System Manager Parameter Store`](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-paramstore.html), so that you have trace when people actually view the password.

## Implementation details
* Cassandra has a class called `org.apache.cassandra.cql3.CustomPayloadMirroringQueryHandler`. In that class, we know that Cassandra has a magic property called `cassandra.custom_query_handler_class`.
* In `cassandra.yaml`, we have properties named `authenticator`, `authorizer` and `role_manager` for authentication/authorization.

## Deploy this Audit plugin to Cassansdra
* Put the built jar (`mvn clean install`) file to Cassandra `/lib` folder. For Cassandra installed with `brew` on Mac, just run `install.sh` in this repo (I assume the version is 3.11.2, the latest version when I write this). For Cassandra installed on Ubuntu, it should be at `/usr/share/cassandra/lib/`.
* Add the following to `/etc/cassandra/logback.xml` (Or `/usr/local/etc/cassandra/logback.xml` for Mac users)

```
  <appender name="AUDIT-FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>${cassandra.logdir}/audit.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy">
      <fileNamePattern>${cassandra.logdir}/audit.log.%i.zip</fileNamePattern>
      <minIndex>1</minIndex>
      <maxIndex>20</maxIndex>
    </rollingPolicy>

    <triggeringPolicy class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
      <maxFileSize>20MB</maxFileSize>
    </triggeringPolicy>
    <encoder>
      <pattern>%-5level [%thread] %date{ISO8601} %F:%L - %msg%n</pattern>
      <!-- old-style log format
      <pattern>%5level [%thread] %date{ISO8601} %F (line %L) %msg%n</pattern>
      -->
    </encoder>
  </appender>
  <logger name="com.cassandra.audit" level="INFO" additivity="false">
    <appender-ref ref="AUDIT-FILE"/>
  </logger>
```
The audit file will be at `${cassandra.logdir}/audit.log`.

* add the following to /etc/cassandra/jvm.options (Or `/usr/local/etc/cassandra/jvm.options` for Mac users).

```
-Dcassandra.custom_query_handler_class=com.cassandra.audit.AuditQueryHandler
-Dldap-server-addr=example.com
#-Dldap-server-port=636 (default to 636, could change)
-Dldap-base-dn=dc=example,dc=com
-Dallow-empty-pass=true
-Dldap-cassandra-user-group=sudo
#-Dldap-sys-username=ldap-sys-username (default to ldap-sys-username, could change)
#-Dldap-sys-userpass=ldap-sys-userpass (default to ldap-sys-userpass, could change)
-Dcassandra-system-username=cassandra-username
-Dcassandra-system-userpass=cassandra-password
-Dcassandra-readonly-username=cassandra-readonly-username
-Dcassandra-readonly-userpass=cassandra-readonly-password
```

The Plugin will assume `ldap-sys-username`, `ldap-sys-userpass`, `cassandra-username`, `cassandra-password` are in `AWS System Manager Parameter Store`. And the Cassandra EC2 instance should have access to those parameters. 

The IAM policy file for Cassandra instances could be like this: 

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:ssm:eu-west-1:account-id:parameter/cassandra-username",
                "arn:aws:ssm:eu-west-1:account-id:parameter/cassandra-password",
                "arn:aws:ssm:eu-west-1:account-id:parameter/cassandra-readonly-username",
                "arn:aws:ssm:eu-west-1:account-id:parameter/cassandra-readonly-password",
                "arn:aws:ssm:eu-west-1:account-id:parameter/ldap-sys-username",
                "arn:aws:ssm:eu-west-1:account-id:parameter/ldap-sys-userpass"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "arn:aws:kms:eu-west-1:account-id:key/x12345xx-1x2x-1x2x-1xx2-123456x1234x"
            ]
        }
    ]
}
```

By the way, Mac users might need to add the following to `/usr/local/etc/cassandra/cassandra-env.sh`, in order for `jvm.options` to be picked up during Cassandra start.

```
# Read user-defined JVM options from jvm.options file
JVM_OPTS_FILE=$CASSANDRA_CONF/jvm.options
for opt in `grep "^-" $JVM_OPTS_FILE`
do
  JVM_OPTS="$JVM_OPTS $opt"
done
```

* Edit ` /etc/cassandra/cassandra.yaml` (Or `/usr/local/etc/cassandra/cassandra.yaml` for Mac users)

Change

```
authenticator: AllowAllAuthenticator
authorizer: AllowAllAuthorizer
role_manager: CassandraRoleManager
```

to

```
authenticator: com.cassandra.audit.LdapAuthenticator
authorizer: com.cassandra.audit.Authorizer
role_manager: com.cassandra.audit.LdapRoleManager
```

* Restart Cassandra elegantly. 
