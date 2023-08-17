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

    public static final String DOT_CLUSTER_SESSION = "DOT_CLUSTER_SESSION";

    private final Log log = LogFactory.getLog(RedisSession.class);

    protected static boolean manualDirtyTrackingSupportEnabled = false;

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

    protected static String manualDirtyTrackingAttributeKey = "__changed__";

    /**
     * Allows you to customize name of the attribute used to let the plugin know that the session must be persisted to
     * Redis, no matter what.
     *
     * @param key The name of the flag attribute.
     */
    public static void setManualDirtyTrackingAttributeKey(final String key) {
        manualDirtyTrackingAttributeKey = key;
    }

    protected HashMap<String, Object> changedAttributes;
    protected boolean dirty = false;

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
     * Binds an object to this session, using the specified name. If an object of the same name is already bound to this
     * session, the object is replaced. When calling this method, the plugin will automatically save the session <b>ONLY
     * when the following conditions are met</b>:
     * <ol>
     *     <li>The {@code TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES} contains the
     *     {@link RedisSessionManager.SessionPersistPolicy#SAVE_ON_CHANGE} policy in it.</li>
     *     <li>If it does, then at least one of the following criteria must be met:</li>
     *     <ol>
     *         <li>Either the new value or the existing value of the added attribute <b>ARE NOT NULL</b>.</li>
     *         <li>The class of the new value compared to the existing value is different.</li>
     *         <li>The new value is actually different from the existing value.</li>
     *     </ol>
     * </ol>
     * <p>
     * After this method executes, and if the object implements <code>HttpSessionBindingListener</code>, the container
     * calls <code>valueBound()</code> on the object.
     *
     * @param key   Name to which the object is bound, cannot be null
     * @param value Object to be bound. If it's {@code null}, it'll be removed from the session.
     *
     * @throws IllegalArgumentException if an attempt is made to add a non-serializable object in an environment marked
     *                                  distributable.
     * @throws IllegalStateException    if this method is called on an invalidated session.
     */
    @Override
    public void setAttribute(final String key, final Object value) {
        if (manualDirtyTrackingSupportEnabled && manualDirtyTrackingAttributeKey.equals(key)) {
            this.dirty = true;
            return;
        }
        final Object oldValue = getAttribute(key);
        if (value instanceof Serializable) {
            super.setAttribute(key, value);
        } else {
            if (null != value) {
                log.warn(String.format("Value of key '%s' is not serializable. Removing it from Session '%s'", key,
                        this.id));
            }
            super.removeAttribute(key);
        }
        if ((value != null || oldValue != null)
                && (value == null && oldValue != null
                || oldValue == null && value != null
                || !value.getClass().isInstance(oldValue)
                || !value.equals(oldValue))) {
            if (this.manager instanceof RedisSessionManager && ((RedisSessionManager) this.manager).getSaveOnChange()) {
                try {
                    ((RedisSessionManager) this.manager).save(this, true);
                } catch (final IOException ex) {
                    log.error("Error saving session '" + this.id + "' on setAttribute (triggered by saveOnChange=true): " + ex.getMessage());
                }
            } else {
                this.changedAttributes.put(key, value);
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
            log.error(e);
            throw e;
        }
    }

    @Override
    public void readObjectData(final java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            super.readObjectData(in);
            this.setCreationTime(in.readLong());
        } catch (final Exception e) {
            log.error(e);
            throw e;
        }
    }

}
