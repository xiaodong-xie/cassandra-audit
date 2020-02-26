package com.cassandra.audit;

import static com.cassandra.audit.Utils.READONLY_USERS;

import java.util.HashSet;
import java.util.Set;
import org.apache.cassandra.auth.AllowAllAuthorizer;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;

public class Authorizer extends AllowAllAuthorizer {

    private static final Set<Permission> READONLY_PERMISSIONS;

    static {
        Set<Permission> temp = new HashSet<>();
        temp.add(Permission.SELECT);
        temp.add(Permission.DESCRIBE);
        READONLY_PERMISSIONS = temp;
    }

    @Override
    public boolean requireAuthorization() {
        return true;
    }

    @Override
    public Set<Permission> authorize(AuthenticatedUser user, IResource resource) {
        String userName = user.getName();
        if (READONLY_USERS.contains(userName)) {
            return READONLY_PERMISSIONS;
        }
        return Permission.ALL;
    }
}
