package com.dotcms.tomcat.redissessions;

import org.apache.catalina.Manager;
import org.apache.catalina.session.StandardSession;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.IOException;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;

/**
 * Extends the current {@link StandardSession} class with additional functionality that allows it to interact with the
 * Redis Session Manager. Contains specific attributes and behavior required by the Manager to correctly operate.
 */
public class RedisSession extends StandardSession {

    private static final long serialVersionUID = 1L;

    private final Log log = LogFactory.getLog(RedisSession.class);

    public static final String DOT_CLUSTER_SESSION_ATTR = "DOT_CLUSTER_SESSION";

    protected HashMap<String, Object> changedAttributes;
    protected boolean dirty = false;

    protected static String manualDirtyTrackingAttributeKey = "__dot_session_attribute_changed__";
    protected static String persistOnDemandAttributeKey = "__dot_session_persist_now__";

    protected static boolean manualDirtyTrackingSupportEnabled = true;
    protected static boolean persistOnDemandEnabled = true;

    /**
     * Activates a feature in the Redis-enabled Session Manager that allows developers to send a specific attribute to
     * indicate the plugin that the Session must be saved, no matter what. You can customize the attribute's name via
     * the {@link #setManualDirtyTrackingAttributeKey(String)} method.
     * <p>If you have a {@link java.util.List} as your attribute, and you add or remove elements to it, the plugin will
     * not be able to detect that change. Using the manual dirty tracking allows you to force the plugin to save the
     * session instead of letting it make the choice.</p>
     *
     * @param enabled If {@code true}, developers will be able to ask the plugin to force saving a session.
     */
    public static void setManualDirtyTrackingSupportEnabled(final boolean enabled) {
        manualDirtyTrackingSupportEnabled = enabled;
    }

    /**
     * Allows you to customize name of the attribute used to let the plugin know that the session must be persisted to
     * Redis, no matter what.
     *
     * @param key The name of the flag attribute.
     */
    public static void setManualDirtyTrackingAttributeKey(final String key) {
        manualDirtyTrackingAttributeKey = key;
    }

    /**
     * Allows you to customize name of the attribute used to let the plugin know that the session must be persisted to
     * Redis, no matter what.
     *
     * @param key The name of the flag attribute.
     */
    public static void setPersistOnDemandAttributeKey(final String key) {
        persistOnDemandAttributeKey = key;
    }

    public RedisSession(final Manager manager) {
        super(manager);
        this.resetDirtyTracking();
    }

    /**
     * Determines whether the current session has changed since the last time it was saved based on the following
     * criteria:
     * <ul>
     *     <li>The {@code dirty} flag has been set to {@code true}.</li>
     *     <li>The Map containing the attributes that have changed is NOT empty.</li>
     * </ul>
     *
     * @return If the session is dirty, returns {@code true}.
     */
    public boolean isDirty() {
        return this.dirty || !this.changedAttributes.isEmpty();
    }

    /**
     * Returns the Map containing the attributes that have changed since the last time the session was saved.
     *
     * @return A Map containing the attributes that have changed.
     */
    public HashMap<String, Object> getChangedAttributes() {
        return this.changedAttributes;
    }

    /**
     * Resets the current session to an empty initial state. This method must be called every time (1) the session is
     * persisted to Redis, and (2) read/deserialized from Redis.
     */
    public void resetDirtyTracking() {
        this.changedAttributes = new HashMap<>();
        this.dirty = false;
    }

    /**
     * Binds an object to this session, using the specified name. If an object of the same name is
     * already bound to this session, the object is replaced. When calling this method, the plugin
     * will automatically save the session <b>ONLY when the following conditions are met</b>:
     * <ol>
     *     <li>The {@code TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES} contains the
     *     {@link RedisSessionManager.SessionPersistPolicy#SAVE_ON_CHANGE} policy in it.</li>
     *     <li>If it does, then at least one of the following criteria must be met:</li>
     *     <li>Either the new value or the existing value of the added attribute <b>ARE NOT
     *     NULL</b>.</li>
     *     <li>The class of the new value compared to the existing value is different.</li>
     *     <li>The new value is actually different from the existing value.</li>
     * </ol>
     * <p>
     * After this method executes, and if the object implements
     * <code>HttpSessionBindingListener</code>, the container calls <code>valueBound()</code> on the
     * object.
     *
     * @param key           Name to which the incoming value is bound.
     * @param incomingValue Object to be bound. It must be serializable and not {@code null}. If it
     *                      is {@code null}, then it'll be removed from the session.
     *
     * @throws IllegalArgumentException if an attempt is made to add a non-serializable object in an
     *                                  environment marked distributable.
     * @throws IllegalStateException    if this method is called on an invalidated session.
     */
    @Override
    public void setAttribute(final String key, final Object incomingValue) {
        if (manualDirtyTrackingSupportEnabled && manualDirtyTrackingAttributeKey.equals(key)) {
            log.info(String.format("Manual dirty tracking key '%s' was found. Marking session as dirty.", key));
            this.dirty = true;
            return;
        }
        if (incomingValue instanceof Serializable) {
            super.setAttribute(key, incomingValue);
        } else {
            if (null != incomingValue) {
                log.warn(String.format("Value of key '%s' is not serializable. Removing it from Session '%s'", key,
                        this.id));
                super.setAttribute(key, null);
                return;
            }
        }
        if (persistOnDemandEnabled && persistOnDemandAttributeKey.equals(key)) {
            log.info(String.format("Persist-on-demand key '%s' was found. Saving session now.", key));
            this.saveSession("persistOnDemand=true");
            return;
        }
        final Object oldValue = getAttribute(key);
        if ((incomingValue != null || oldValue != null)
                && (incomingValue == null && oldValue != null
                || oldValue == null && incomingValue != null
                || !incomingValue.getClass().isInstance(oldValue)
                || !incomingValue.equals(oldValue))) {
            if (((RedisSessionManager) this.manager).getSaveOnChange()) {
                this.saveSession("saveOnChange=true");
            } else {
                this.changedAttributes.put(key, incomingValue);
            }
        }
    }

    /**
     * Persists the current HTTP Session to Redis.
     *
     * @param triggeredBy A simple logging message for indicating what feature triggered this save.
     */
    private void saveSession(final String triggeredBy) {
        if (this.manager instanceof RedisSessionManager) {
            try {
                ((RedisSessionManager) this.manager).save(this, true);
            } catch (final IOException ex) {
                log.error(String.format("Error persisting session '%s' on setAttribute (triggered by %s): " +
                        "%s", this.id, triggeredBy, ex.getMessage()));
            }
        }
    }

    @Override
    public void removeAttribute(final String name) {
        super.removeAttribute(name);
        if (this.manager instanceof RedisSessionManager && ((RedisSessionManager) this.manager).getSaveOnChange()) {
            try {
                ((RedisSessionManager) this.manager).save(this, true);
            } catch (final IOException ex) {
                log.error("Error saving session on removeAttribute with name '" + name + "' (triggered by saveOnChange=true): " + ex.getMessage());
            }
        } else {
            this.dirty = true;
        }
    }

    @Override
    public void setId(final String id) {
        // Specifically do not call super(): it's implementation does unexpected things
        // like calling manager.remove(session.id) and manager.add(session).
        this.id = id;
    }

    @Override
    public void setPrincipal(final Principal principal) {
        this.dirty = true;
        super.setPrincipal(principal);
    }

    @Override
    public void writeObjectData(final java.io.ObjectOutputStream out) throws IOException {
        try {
            super.writeObjectData(out);
            out.writeLong(this.getCreationTime());
        } catch (final Exception e) {
            log.error(String.format("Failed to write object data from Session ID '%s': %s",
                    this.getId(), e.getMessage()), e);
            throw e;
        }
    }

    @Override
    public void readObjectData(final java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            super.readObjectData(in);
            this.setCreationTime(in.readLong());
        } catch (final Exception e) {
            log.error(String.format("Failed to read object data into Session ID '%s': %s",
                    this.getId(), e.getMessage()), e);
            throw e;
        }
    }

    /**
     * Returns the valid flag from the base class without triggering expiration checks.
     * This is used internally by the overridden {@link #isValid()} method for Redis-managed sessions.
     *
     * @return {@code true} if the session is marked as valid, {@code false} otherwise
     */
    protected boolean getValidFlag() {
        return this.isValid;
    }

    /**
     * Returns the last accessed time for this session, calculated from Redis TTL.
     *
     * <p><b>How It Works</b>:</p>
     * <ul>
     *     <li>Queries Redis for remaining TTL on the session key</li>
     *     <li>Determines the original Redis TTL based on session type:
     *         <ul>
     *             <li>Undefined sessions: uses undefinedSessionTypeTimeout (15s)</li>
     *             <li>Authenticated sessions: uses maxInactiveInterval (1800s)</li>
     *         </ul>
     *     </li>
     *     <li>Calculates: lastAccessedTime = currentTime - (originalTTL - remainingTTL)</li>
     *     <li>Compares with stored lastAccessedTime from base class</li>
     *     <li>Returns the most recent (max) to ensure accuracy</li>
     * </ul>
     *
     * <p><b>Why This Works for All Session Types</b>:</p>
     * <ul>
     *     <li><b>Tomcat-managed sessions (undefined)</b>: maxInactiveInterval = Tomcat's default session timeout
     *     (typically 1800s or as configured in web.xml). Redis stores with short TTL (15s) for cluster
     *     coordination only.</li>
     *     <li><b>Redis-managed sessions (authenticated)</b>: maxInactiveInterval = userSessionTimeout (1800s),
     *     synchronized with Redis TTL for cluster-consistent expiration.</li>
     *     <li>TTL calculation works the same way for both types</li>
     * </ul>
     *
     * <p><b>Why Return Max(calculated, stored)</b>:</p>
     * <ul>
     *     <li>If TTL-based calculation is more recent → use it (handles stale stored value)</li>
     *     <li>If stored value is more recent → use it (handles edge cases in TTL calculation)</li>
     *     <li>Always returns the most up-to-date last access time</li>
     *     <li>Robust against both stale serialization and TTL edge cases</li>
     * </ul>
     *
     * <p><b>Stale Timestamp Problem</b>:</p>
     * <p>When a session is saved to and loaded from Redis multiple times, the stored
     * lastAccessedTime becomes stale. Redis TTL is refreshed on every access, making it
     * the accurate source of truth. By calculating from TTL and comparing with stored value,
     * we ensure the most accurate timing information.</p>
     *
     * @return The time this session was last accessed, in milliseconds since epoch (most recent value)
     */
    @Override
    public long getLastAccessedTime() {
        // Check validity first
        if (!getValidFlag()) {
            throw new IllegalStateException(
                    sm.getString("standardSession.getLastAccessedTime.ise"));
        }

        if (this.manager instanceof RedisSessionManager) {
            final RedisSessionManager redisManager = (RedisSessionManager) this.manager;

            try {
                final long remainingTTL = redisManager.getRemainingTTL(this.getId());

                if (remainingTTL >= 0) {
                    // Determine the original TTL that was set in Redis (not maxInactiveInterval!)
                    // For undefined sessions: Redis TTL = undefinedSessionTypeTimeout (15s)
                    // For authenticated sessions: Redis TTL = userSessionTimeout (1800s)
                    final long originalTTL;
                    if (this.getAttribute(DOT_CLUSTER_SESSION_ATTR) != null || redisManager.isAnonTrafficEnabled()) {
                        // Authenticated session: Redis TTL matches maxInactiveInterval
                        originalTTL = this.getMaxInactiveInterval();
                    } else {
                        // Undefined session: Redis TTL is the short timeout (not maxInactiveInterval)
                        originalTTL = redisManager.getUndefinedSessionTypeTimeout();
                    }
                    final long timeSinceLastAccess = (originalTTL - remainingTTL) * 1000L;
                    final long currentTime = System.currentTimeMillis();
                    final long calculatedLastAccessedTime = currentTime - timeSinceLastAccess;

                    // Get stored lastAccessedTime from base class (safe now - we checked validity)
                    final long storedLastAccessedTime = super.getLastAccessedTime();

                    // Return the most recent (max) to ensure we have the most up-to-date value
                    // This handles both stale stored values and edge cases in TTL calculation
                    return Math.max(calculatedLastAccessedTime, storedLastAccessedTime);
                }
            } catch (Exception e) {
                // Fall back to stored value if Redis is unavailable
                log.warn(String.format("Error getting remaining TTL for session [ %s ]. " +
                        "Falling back to stored lastAccessedTime: %s", this.getId(), e.getMessage()));
            }
        }

        // Fallback: Use stored lastAccessedTime (safe - we checked validity above)
        return super.getLastAccessedTime();
    }

    /**
     * Checks if the session is valid, with different behavior based on session type:
     *
     * <p><b>For Redis-managed sessions</b> (sessions with DOT_CLUSTER_SESSION_ATTR or when
     * TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true):</p>
     * <ul>
     *     <li>Only checks the session's valid flag</li>
     *     <li>DOES NOT check lastAccessedTime or maxInactiveInterval</li>
     *     <li>Expiration is managed by Redis TTL, not Tomcat idle time</li>
     * </ul>
     *
     * <p><b>For Tomcat-managed sessions</b> (undefined sessions without DOT_CLUSTER_SESSION_ATTR
     * when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false):</p>
     * <ul>
     *     <li>Delegates to base class {@code super.isValid()}</li>
     *     <li>Includes idle time expiration checks (lastAccessedTime + maxInactiveInterval)</li>
     *     <li>Base class will automatically call {@code expire()} if session is expired</li>
     * </ul>
     *
     * <p>This separation ensures that Redis-managed sessions are not prematurely expired by
     * Tomcat's local expiration logic, which would cause inconsistent expiration across cluster
     * nodes.</p>
     *
     * @return {@code true} if the session is valid, {@code false} otherwise
     */
    @Override
    public boolean isValid() {
        // Check valid flag FIRST before accessing attributes
        if (!getValidFlag()) {
            return false;
        }

        if (this.manager instanceof RedisSessionManager) {
            final RedisSessionManager redisManager = (RedisSessionManager) this.manager;

            // Now safe to check attributes since we know session is valid
            // Check if this is a Redis-managed session
            final boolean isRedisManagedSession =
                    this.getAttribute(DOT_CLUSTER_SESSION_ATTR) != null
                    || redisManager.isAnonTrafficEnabled();

            if (isRedisManagedSession) {
                // Redis-managed: Only check valid flag, skip idle time checks
                // Expiration is managed by Redis TTL
                return true;  // Already checked valid flag above
            }
        }

        // Tomcat-managed: Delegate to base class which includes idle time expiration
        return super.isValid();
    }

}
