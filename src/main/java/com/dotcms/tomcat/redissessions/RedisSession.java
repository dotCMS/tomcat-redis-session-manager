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

    public static void setManualDirtyTrackingSupportEnabled(boolean enabled) {
        manualDirtyTrackingSupportEnabled = enabled;
    }

    protected static String manualDirtyTrackingAttributeKey = "__changed__";

    public static void setManualDirtyTrackingAttributeKey(String key) {
        manualDirtyTrackingAttributeKey = key;
    }

    protected HashMap<String, Object> changedAttributes;
    protected boolean dirty = false;

    public RedisSession(Manager manager) {
        super(manager);
        resetDirtyTracking();
    }

    public boolean isDirty() {
        return dirty || !changedAttributes.isEmpty();
    }

    public HashMap<String, Object> getChangedAttributes() {
        return changedAttributes;
    }

    public void resetDirtyTracking() {
        changedAttributes = new HashMap<>();
        dirty = false;
    }

    @Override
    public void setAttribute(final String key, final Object value) {
        if (manualDirtyTrackingSupportEnabled && manualDirtyTrackingAttributeKey.equals(key)) {
            dirty = true;
            return;
        }
        final Object oldValue = getAttribute(key);
        if (value instanceof Serializable) {
            super.setAttribute(key, value);
        } else {
            log.warn(String.format("Value of key '%s' is null or not serializable. Removing it from Session '%s'",
                    key, this.id));
            super.removeAttribute(key);
        }
        if ((value != null || oldValue != null) && (value == null && oldValue != null || oldValue == null && value != null
                        || !value.getClass().isInstance(oldValue) || !value.equals(oldValue))) {
            if (this.manager instanceof RedisSessionManager && ((RedisSessionManager) this.manager).getSaveOnChange()) {
                try {
                    ((RedisSessionManager) this.manager).save(this, true);
                } catch (final IOException ex) {
                    log.error("Error saving session '" + this.id + "' on setAttribute (triggered by saveOnChange=true): " + ex.getMessage());
                }
            } else {
                changedAttributes.put(key, value);
            }
        }
    }

    @Override
    public void removeAttribute(String name) {
        super.removeAttribute(name);
        if (this.manager instanceof RedisSessionManager && ((RedisSessionManager) this.manager).getSaveOnChange()) {
            try {
                ((RedisSessionManager) this.manager).save(this, true);
            } catch (IOException ex) {
                log.error("Error saving session on setAttribute (triggered by saveOnChange=true): " + ex.getMessage());
            }
        } else {
            dirty = true;
        }
    }

    @Override
    public void setId(String id) {
        // Specifically do not call super(): it's implementation does unexpected things
        // like calling manager.remove(session.id) and manager.add(session).

        this.id = id;
    }

    @Override
    public void setPrincipal(Principal principal) {
        dirty = true;
        super.setPrincipal(principal);
    }

    @Override
    public void writeObjectData(java.io.ObjectOutputStream out) throws IOException {
        try {
            super.writeObjectData(out);
            out.writeLong(this.getCreationTime());
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }

    @Override
    public void readObjectData(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            super.readObjectData(in);
            this.setCreationTime(in.readLong());
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }

}
