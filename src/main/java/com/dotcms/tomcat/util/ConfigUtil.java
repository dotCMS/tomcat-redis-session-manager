package com.dotcms.tomcat.util;

import org.apache.catalina.connector.Request;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;

/**
 * Utility class that provides useful methods to access configuration properties for this plugin.
 *
 * @author Jose Castro
 * @since May 3rd, 2023
 */
public class ConfigUtil {

    public static final String REDIS_HOST_PROPERTY = "${TOMCAT_REDIS_SESSION_HOST}";
    public static final String REDIS_PORT_PROPERTY = "${TOMCAT_REDIS_SESSION_PORT}";
    public static final String REDIS_PASSWORD_PROPERTY = "${TOMCAT_REDIS_SESSION_PASSWORD}";
    public static final String REDIS_SSL_ENABLED_PROPERTY = "${TOMCAT_REDIS_SESSION_SSL_ENABLED}";
    public static final String REDIS_SENTINEL_MASTER_PROPERTY = "${TOMCAT_REDIS_SESSION_SENTINEL_MASTER}";
    public static final String REDIS_SENTINELS_PROPERTY = "${TOMCAT_REDIS_SESSION_SENTINELS}";
    public static final String REDIS_DATABASE_PROPERTY = "${TOMCAT_REDIS_SESSION_DATABASE}";
    public static final String REDIS_TIMEOUT_PROPERTY = "${TOMCAT_REDIS_SESSION_TIMEOUT}";
    public static final String REDIS_MAX_CONNECTIONS_PROPERTY = "${TOMCAT_REDIS_MAX_CONNECTIONS}";
    public static final String REDIS_MAX_IDLE_CONNECTIONS_PROPERTY = "${TOMCAT_REDIS_MAX_IDLE_CONNECTIONS";
    public static final String REDIS_MIN_IDLE_CONNECTIONS_PROPERTY = "${TOMCAT_REDIS_MAX_IDLE_CONNECTIONS";
    public static final String REDIS_PERSISTENT_POLICIES_PROPERTY = "${TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES}";

    public static final String DOTCMS_CLUSTER_ID_PROPERTY = "${DOT_DOTCMS_CLUSTER_ID}";
    public static final String REDIS_ENABLED_FOR_ANON_TRAFFIC = "${TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC}";

    public static final Set<String> BACKEND_FILTERED_REQUESTS = Stream.of(
            "/api",
            "/webdav",
            "/c/",
            "/html",
            "/dotAdmin",
            "/custom-elements",
            "/dotcms-webcomponents",
            "/dwr").collect(Collectors.collectingAndThen(toSet(), Collections::unmodifiableSet));

    /**
     * Returns the String value of the specified configuration property. Such a key can represent a Java Property or an
     * Environment Variable.
     *
     * @param key The key of the configuration property to be retrieved.
     *
     * @return The String value of the specified configuration property.
     */
    public static String getConfigProperty(String key) {
        if (null == key) {
            return null;
        }
        int fromIndex = 0;
        while (true) {
            final int beginIndex = key.indexOf("${", fromIndex);
            final int endIndex = key.indexOf("}", fromIndex);
            if (beginIndex < 0 || endIndex < 0) {
                break;
            }
            final String expression = key.substring(beginIndex + 2, endIndex);
            String value = System.getProperty(expression);
            if (null == value || value.isEmpty()) {
                value = System.getenv(expression);
            }
            if (value == null || value.isEmpty()) {
                fromIndex = endIndex + 1;
                continue;
            }
            key = key.replace(String.format("${%s}", expression), value);
        }
        return key;
    }

    /**
     * Returns the String value of the specified configuration property. Such a key can represent a Java Property or an
     * Environment Variable. If the value of such a key is null or equals to the key itself, then the specified default
     * value is returned.
     *
     * @param key          The key of the configuration property to be retrieved.
     * @param defaultValue The default value to be returned if the specified configuration property is not found.
     *
     * @return The String value of the specified configuration property.
     */
    public static <T> T getConfigProperty(String key, final T defaultValue) {
        final Object propertyValue = getConfigProperty(key);
        if (null == propertyValue || key.equals(propertyValue)) {
            return defaultValue;
        }
        if (defaultValue instanceof Integer) {
            return (T) Integer.valueOf(propertyValue.toString());
        }
        if (defaultValue instanceof Long) {
            return (T) Long.valueOf(propertyValue.toString());
        }
        if (defaultValue instanceof Boolean) {
            return (T) Boolean.valueOf(propertyValue.toString());
        }
        return (T) propertyValue;
    }

    /**
     * Determines whether the URL specified in the HTTP Request maps to the dotCMS back-end or not.
     *
     * @param request The current {@link Request} object.
     *
     * @return If the incoming URL belongs to the dotCMS back-end, returns {@code true}.
     */
    public static boolean isBackEndRequest(final Request request) {
        return null != request.getRequestURI() && BACKEND_FILTERED_REQUESTS.stream().anyMatch(backEndUrl -> request.getRequestURI().startsWith(backEndUrl));
    }

}
