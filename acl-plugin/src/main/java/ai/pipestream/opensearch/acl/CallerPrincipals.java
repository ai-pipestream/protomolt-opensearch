package ai.pipestream.opensearch.acl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Principal keys of the caller, read from the user info the OpenSearch Security plugin puts in the thread context.
 */
public final class CallerPrincipals {

    /** Thread context transient where the Security plugin stores the authenticated user's info. */
    public static final String SECURITY_USER_INFO_TRANSIENT = "_opendistro_security_user_info";

    private CallerPrincipals() {
    }

    /**
     * Parses the Security plugin user info into principal keys: the user name followed by each backend role.
     * The format is {@code name|backendrole1,backendrole2|role1,role2|tenant|...} with literal pipes escaped as
     * {@code \|}.
     *
     * @param userInfo the user info string, or null when no user is authenticated
     * @return the principal keys, empty when there is no authenticated user
     */
    public static Set<String> fromSecurityUserInfo(String userInfo) {
        Set<String> principals = new LinkedHashSet<>();
        if (userInfo == null || userInfo.isEmpty()) {
            return principals;
        }
        List<String> fields = splitOnUnescapedPipe(userInfo);
        String name = fields.get(0).strip();
        if (name.isEmpty()) {
            return principals;
        }
        principals.add(name);
        if (fields.size() > 1) {
            for (String role : splitOnComma(fields.get(1))) {
                if (!role.isEmpty()) {
                    principals.add(role);
                }
            }
        }
        return principals;
    }

    private static List<String> splitOnUnescapedPipe(String value) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length() && value.charAt(i + 1) == '|') {
                current.append('|');
                i += 2;
            } else if (c == '|') {
                fields.add(current.toString());
                current.setLength(0);
                i++;
            } else {
                current.append(c);
                i++;
            }
        }
        fields.add(current.toString());
        return fields;
    }

    private static List<String> splitOnComma(String value) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        for (int i = 0; i <= value.length(); i++) {
            if (i == value.length() || value.charAt(i) == ',') {
                parts.add(value.substring(start, i));
                start = i + 1;
            }
        }
        return parts;
    }
}
