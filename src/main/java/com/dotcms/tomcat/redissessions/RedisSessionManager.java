package com.dotcms.tomcat.redissessions;

import com.dotcms.tomcat.util.ConfigUtil;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Loader;
import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.session.ManagerBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import redis.clients.jedis.ConnectionPoolConfig;
import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.UnifiedJedis;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * This Redis-Based Tomcat Session implementation provides the session creation, saving, and loading functionality for
 * dotCMS. For clustered environments, Persisted Sessions allow the system the possibility to bring one of the nodes
 * down without affecting the current Sessions from one or more Users.
 * <p>This is because they're no longer stored in memory by Tomcat, but in Redis. So, requests from Users can seamlessly
 * bounce from one node of the cluster to another, without causing any issues. In case one of the nodes goes down, there
 * will be no service interruption.</p>
 */
public class RedisSessionManager extends ManagerBase implements Lifecycle {

    /**
     * This Enum allows users to tell this Manager the circumstances in which it must persist a
     * given session to Redis. There are three types of {@link SessionPersistPolicy} values:
     * <ol>
     *      <li>{@link SessionPersistPolicy#DEFAULT}: Selected by default. It tells the manager
     *      to ONLY persist the session in case its current attributes compared to the ones from
     *      Redis are different, which is the usual behavior.</li>
     *      <li>{@link SessionPersistPolicy#SAVE_ON_CHANGE}: It tells the manager to persist the
     *      session as soon as any session attribute is added/changed. This option will degrade
     *      performance slightly as any change to the session will save it synchronously to
     *      Redis.</li>
     *     <li>{@link SessionPersistPolicy#ALWAYS_SAVE_AFTER_REQUEST}: It tells the manager to force
     *      persisting the session as soon as the request finishes. This option make actually
     *      increase the likelihood of race conditions if not all of your requests change the
     *      session.</li>
     * </ol>
     */
    public enum SessionPersistPolicy {

        DEFAULT,
        SAVE_ON_CHANGE,
        ALWAYS_SAVE_AFTER_REQUEST;

        static SessionPersistPolicy fromName(final String name) {
            for (final SessionPersistPolicy policy : SessionPersistPolicy.values()) {
                if (policy.name().equalsIgnoreCase(name)) {
                    return policy;
                }
            }
            return DEFAULT;
        }

    }

    private final Log log = LogFactory.getLog(RedisSessionManager.class);

    protected static final byte[] NULL_SESSION = "null".getBytes(StandardCharsets.UTF_8);

    protected String host = "localhost";
    protected int port = Protocol.DEFAULT_PORT;
    protected String username = null;
    protected String password = null;
    protected boolean ssl = false;
    protected int timeout = Protocol.DEFAULT_TIMEOUT;
    protected int maxTotal = 128;
    protected int maxIdle = 100;
    protected int minIdle = 32;
    protected String prefix = "";
    /**
     * Delimiter appended after the cluster ID prefix so that Redis keys for one cluster cannot collide
     * with another cluster whose ID shares the same leading characters (e.g. cluster {@code "prod"} vs
     * {@code "prod2"}). Without it, {@code "prod" + sessionId} could overlap with {@code "prod2" + sessionId}.
     */
    protected static final String PREFIX_DELIMITER = ":sessions:";
    protected int database = Protocol.DEFAULT_DATABASE;
    protected String sentinelMaster = null;
    protected Set<String> sentinelSet = null;

    protected int userSessionTimeout = 1800;
    protected boolean manualDirtyTrackingSupportEnabled = false;
    protected String manualDirtyTrackingSupportAttr = "";
    protected boolean persistOnDemandEnabled = false;
    protected String persistOnDemandAttr = "";
    protected boolean isAnonTrafficEnabled = false;
    protected int undefinedSessionTypeTimeout = 15;

    protected UnifiedJedis jedisPool;
    protected ConnectionPoolConfig connectionPoolConfig = this.buildPoolConfig();
    protected RedisSessionHandlerValve handlerValve;

    protected ThreadLocal<RedisSession> currentSession = new ThreadLocal<>();
    protected ThreadLocal<SessionSerializationMetadata> currentSessionSerializationMetadata =
                    new ThreadLocal<>();
    protected ThreadLocal<String> currentSessionId = new ThreadLocal<>();
    protected ThreadLocal<Boolean> currentSessionIsPersisted = new ThreadLocal<>();

    /**
     * Number of stripes in {@link #saveLocks}. A power of two keeps {@code id.hashCode()} well distributed
     * across stripes via {@link Math#floorMod(int, int)}, so distinct sessions almost always take different
     * monitors and only same-ID saves contend.
     */
    private static final int SAVE_LOCK_STRIPES = 256;
    /**
     * Striped locks used to serialize {@link #saveInternal(Session, boolean)} <b>by session ID</b>. Locking on
     * the {@link Session} object itself is insufficient because {@link #findSession(String)} deserializes a new
     * {@link RedisSession} instance on every Redis hit, so concurrent requests for the same ID hold different
     * objects. Striping (instead of a per-ID lock map) keeps memory bounded and needs no eviction.
     */
    private final Object[] saveLocks = createSaveLocks();

    private static Object[] createSaveLocks() {
        final Object[] locks = new Object[SAVE_LOCK_STRIPES];
        for (int i = 0; i < locks.length; i++) {
            locks[i] = new Object();
        }
        return locks;
    }

    protected Serializer serializer;
    protected String serializationStrategyClass = JavaSerializer.class.getName();
    protected EnumSet<SessionPersistPolicy> sessionPersistPoliciesSet = EnumSet.of(SessionPersistPolicy.DEFAULT);

    /**
     * Creates the Connection Pool Configuration object for the Redis connection. Here, you can set the most important
     * default values even before the Jedis configuration is initialized.
     *
     * @return The {@link ConnectionPoolConfig} object.
     */
    private ConnectionPoolConfig buildPoolConfig() {
        final ConnectionPoolConfig poolConfig = new ConnectionPoolConfig();
        poolConfig.setMaxTotal(this.maxTotal);
        poolConfig.setMaxIdle(this.maxIdle);
        poolConfig.setMinIdle(this.minIdle);
        return poolConfig;
    }
    
    public boolean getSsl() {
        return this.ssl;
      }

    public void setSsl(final boolean ssl) {
        this.ssl = ssl;
    }
    
    public String getHost() {
        return this.host;
    }

    public void setHost(final String host) {
        this.host = host;
    }

    public int getPort() {
        return this.port;
    }

    public void setPort(final int port) {
        this.port = port;
    }

    public int getDatabase() {
        return this.database;
    }

    public void setDatabase(final int database) {
        this.database = database;
    }

    public int getTimeout() {
        return this.timeout;
    }

    public void setTimeout(final int timeout) {
        this.timeout = timeout;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public void setSerializationStrategyClass(final String strategy) {
        this.serializationStrategyClass = strategy;
    }

    /**
     * Returns the currently specified Session persist policies.
     *
     * @return The specified persist policies in the form of a String with comma-separated values.
     */
    public String getSessionPersistPolicies() {
        final StringBuilder policies = new StringBuilder();
        for (final Iterator<SessionPersistPolicy> iter = this.sessionPersistPoliciesSet.iterator(); iter.hasNext();) {
            final SessionPersistPolicy policy = iter.next();
            policies.append(policy.name());
            if (iter.hasNext()) {
                policies.append(",");
            }
        }
        return policies.toString();
    }

    /**
     * Allows you to set one or more session persist policies for this manager. The policies are set as a String with
     * comma-separated value.
     *
     * @param sessionPersistPolicies The policies to set.
     */
    public void setSessionPersistPolicies(final String sessionPersistPolicies) {
        final String[] policyArray = sessionPersistPolicies.split(",");
        final EnumSet<SessionPersistPolicy> policySet = EnumSet.of(SessionPersistPolicy.DEFAULT);
        for (final String policyName : policyArray) {
            final SessionPersistPolicy policy = SessionPersistPolicy.fromName(policyName);
            policySet.add(policy);
        }
        this.sessionPersistPoliciesSet = policySet;
    }

    /**
     * Sets the {@link SessionPersistPolicy#SAVE_ON_CHANGE} for this Redis Session Manager. Such a policy means that
     * this manager to always persist the current Session if any of its attributes have been modified (default).
     *
     * @return If this policy has been set, returns {@code true}.
     */
    public boolean getSaveOnChange() {
        return this.sessionPersistPoliciesSet.contains(SessionPersistPolicy.SAVE_ON_CHANGE);
    }

    /**
     * Sets the {@link SessionPersistPolicy#ALWAYS_SAVE_AFTER_REQUEST} for this Redis Session Manager. Such a policy
     * means that this manager to persist the current Session after a request has been processed. Even if the Session
     * attributes have not changed at all, this policy will force the Manager to persist it.
     *
     * @return If this policy has been set, returns {@code true}.
     */
    public boolean getAlwaysSaveAfterRequest() {
        return this.sessionPersistPoliciesSet.contains(SessionPersistPolicy.ALWAYS_SAVE_AFTER_REQUEST);
    }

    public String getSentinels() {
        if (null == this.sentinelSet) {
            return null;
        }
        final StringBuilder sentinels = new StringBuilder();
        for (final Iterator<String> iter = this.sentinelSet.iterator(); iter.hasNext();) {
            sentinels.append(iter.next());
            if (iter.hasNext()) {
                sentinels.append(",");
            }
        }
        return sentinels.toString();
    }

    public void setSentinels(String sentinels) {
        if (null == sentinels) {
            sentinels = "";
        }
        final String[] sentinelArray = sentinels.split(",");
        this.sentinelSet = new HashSet<>(Arrays.asList(sentinelArray));
    }

    public Set<String> getSentinelSet() {
        return this.sentinelSet;
    }

    public String getSentinelMaster() {
        return this.sentinelMaster;
    }

    public void setSentinelMaster(String master) {
        this.sentinelMaster = master;
    }

    /**
     * Instructs the Session Manager to persist absolutely all the Sessions it manages to the Redis server, not only the
     * ones generated from a back-end or front-end login.
     *
     * @param anonTrafficEnabled If any kind of session must be persisted to Redis, set this to {@code true}.
     */
    public void setAnonTrafficEnabled(final boolean anonTrafficEnabled) {
        this.isAnonTrafficEnabled = anonTrafficEnabled;
    }

    /**
     * Returns whether anonymous traffic is enabled for Redis session management.
     *
     * @return {@code true} if all sessions (including anonymous) are managed by Redis, {@code false} if only authenticated sessions use Redis expiration.
     */
    public boolean isAnonTrafficEnabled() {
        return this.isAnonTrafficEnabled;
    }

    /**
     * Specifies the Redis TTL (time-to-live) in seconds for undefined sessions (sessions without
     * the {@link RedisSession#DOT_CLUSTER_SESSION_ATTR} attribute). This setting is critical for
     * preventing race conditions in clustered environments during authentication.
     * <p><b>Purpose:</b> When a user first accesses the application (before authentication), a session
     * is created without the {@code DOT_CLUSTER_SESSION_ATTR} attribute. In clustered environments,
     * parallel requests during authentication may arrive at different nodes. Storing these new sessions
     * in Redis temporarily allows all nodes to see the same session and prevents duplicate session creation.</p>
     * <p><b>Dual Storage Behavior (when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false, default):</b></p>
     * <ul>
     *     <li><b>Undefined sessions (no DOT_CLUSTER_SESSION_ATTR):</b>
     *         <ul>
     *             <li>Stored in Red and Tomcat with TTL = {@code undefinedSessionTypeTimeout} (default 15s)</li>
     *             <li>After Redis TTL expires, entry auto-deleted from Redis</li>
     *             <li>Tomcat's {@code processExpires()} manages actual session expiration based on {@code lastAccessedTime}</li>
     *         </ul>
     *     </li>
     *     <li><b>When authenticated (DOT_CLUSTER_SESSION_ATTR is set):</b>
     *         <ul>
     *             <li>Redis TTL updated to {@code userSessionTimeout} (default 1800s)</li>
     *             <li>Remains in both Redis and Tomcat</li>
     *             <li>Redis TTL manages expiration (cluster-consistent)</li>
     *             <li>Tomcat's {@code processExpires()} skips these sessions</li>
     *         </ul>
     *     </li>
     * </ul>
     * <p><b>Note:</b> When {@code TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true}, this parameter is not used
     * for undefined sessions as all sessions (including anonymous) use {@code userSessionTimeout} instead.</p>
     * <p><b>Default:</b> 15 seconds - long enough to handle authentication flows but short enough to
     * quickly clean Redis of anonymous sessions that will be managed locally by Tomcat.</p>
     *
     * @param undefinedSessionTypeTimeout The Redis TTL in seconds for undefined sessions. After this time,
     *                                    the session is auto-deleted from Redis but continues to exist in
     *                                    Tomcat for local expiration management (when
     *                                    TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false).
     */
    public void setUndefinedSessionTypeTimeout(final int undefinedSessionTypeTimeout) {
        this.undefinedSessionTypeTimeout = undefinedSessionTypeTimeout;
    }

    /**
     * Returns the Redis TTL (time-to-live) in seconds for undefined sessions.
     *
     * @return The TTL in seconds for undefined sessions.
     */
    public int getUndefinedSessionTypeTimeout() {
        return this.undefinedSessionTypeTimeout;
    }

    @Override
    public int getRejectedSessions() {
        // Essentially do nothing.
        return 0;
    }

    public void setRejectedSessions(int i) {
        // Do nothing.
    }

    @Override
    public void load() throws ClassNotFoundException, IOException {
        // Not implemented
    }

    @Override
    public void unload() throws IOException {
        // Not implemented
    }

    /**
     * Start this component and implement the requirements of
     * {@link org.apache.catalina.util.LifecycleBase#startInternal()}.
     *
     * @exception LifecycleException if this component detects a fatal error that prevents this
     *            component from being used
     */
    @Override
    protected synchronized void startInternal() throws LifecycleException {
        super.startInternal();
        setState(LifecycleState.STARTING);
        log.info("\n" +
                "========================================================================\n" +
                "\n" +
                "                   Redis-based Tomcat Session plugin\n" +
                "\n" +
                "========================================================================");
        boolean attachedToValve = false;
        for (final Valve valve : getContext().getPipeline().getValves()) {
            if (valve instanceof RedisSessionHandlerValve) {
                log.info(String.format("-> Attaching '%s' to '%s'", RedisSessionManager.class.getName(), valve.getClass().getName()));
                this.handlerValve = (RedisSessionHandlerValve) valve;
                this.handlerValve.setRedisSessionManager(this);
                attachedToValve = true;
                break;
            }
        }
        if (!attachedToValve) {
            final String error = "FATAL - Unable to attach to session handling valve. Sessions cannot be saved";
            log.fatal(error);
            throw new LifecycleException(error);
        }
        try {
            this.initializeSerializer();
        } catch (final ClassNotFoundException | NoSuchMethodException | InvocationTargetException |
                       InstantiationException | IllegalAccessException e) {
            log.fatal(String.format("FATAL - Unable to load Java Serializer: %s", e.getMessage()));
            log.debug(e);
            throw new LifecycleException(e);
        }
        this.initializeConfigParams();
        this.initializeRedisConnection();
        getContext().setDistributable(true);
    }

    /**
     * Stop this component and implement the requirements of
     * {@link org.apache.catalina.util.LifecycleBase#stopInternal()}.
     *
     * @exception LifecycleException if this component detects a fatal error that prevents this
     *            component from being used
     */
    @Override
    protected synchronized void stopInternal() throws LifecycleException {
        log.info("Stopping");
        setState(LifecycleState.STOPPING);
        jedisPool = null;
        // Require a new random number generator if we are restarted
        super.stopInternal();
    }

    @Override
    public Session createSession(final String requestedSessionId) {
        RedisSession session = null;
        final String jvmRoute = this.getJvmRoute();
        // Ensure generation of a unique session identifier.
        final String sessionId = null != requestedSessionId
                                         ? this.sessionIdWithJvmRoute(requestedSessionId, jvmRoute)
                                         : this.sessionIdWithJvmRoute(this.generateSessionId(), jvmRoute);
        if (null != sessionId) {
            session = (RedisSession) this.createEmptySession();
            session.setNew(true);
            session.setValid(true);
            session.setCreationTime(System.currentTimeMillis());
            // Set maxInactiveInterval to Tomcat's default timeout
            // This is appropriate for undefined (Tomcat-managed) sessions
            // For authenticated sessions, this will be updated to userSessionTimeout
            // when setSessionExpiration() is called during save()
            session.setMaxInactiveInterval(this.getTomcatSessionTimeoutInSeconds());
            session.setId(sessionId);
            session.tellNew();
        }
        currentSession.set(session);
        currentSessionId.set(sessionId);
        currentSessionIsPersisted.set(false);
        currentSessionSerializationMetadata.set(new SessionSerializationMetadata());
        log.debug(String.format("Session [ %s ] has been created", sessionId));
        return session;
    }

    /**
     * Determines whether the current Session must be persisted to Redis or not. In order to figure this out, a specific
     * parameter named {@code "DOT_CLUSTER_SESSION"} is added by the {@code com.dotcms.listeners.SessionMonitor} class
     * in dotCMS in order to spot Sessions that are being created by both the back-end and the front-end. If that's the
     * case, then it must always be persisted. These are the User Sessions that can be seen in the <b>Settings >
     * Maintenance > Logged Users</b> portlet.
     * <p>However, if the {@link ConfigUtil#REDIS_ENABLED_FOR_ANON_TRAFFIC} property is set to true, then even Sessions
     * coming from front-end requests must be persisted as well.</p>
     *
     * @param session The current {@link Session}.
     *
     * @return If the current Session must be persisted to Redis, returns {@code true}.
     */
    private boolean isSessionPersistable(final Session session) {
        boolean persistable = false;
        // Check session is valid before accessing attributes
        if (null != session && session.isValid()) {
            final Object attrValue = ((RedisSession) session).getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR);
            if (null != attrValue) {
                persistable = (boolean) attrValue;
            }
        }
        return persistable || this.isAnonTrafficEnabled;
    }

    /**
     * Takes an existing Session ID and the resulting JVM Route, and generates a new Session ID.
     *
     * @param sessionId The existing Session ID.
     * @param jvmRoute  The JVM Route.
     *
     * @return The new Session ID.
     */
    private String sessionIdWithJvmRoute(final String sessionId, final String jvmRoute) {
        if (jvmRoute != null) {
            final String jvmRoutePrefix = '.' + jvmRoute;
            return sessionId.endsWith(jvmRoutePrefix) ? sessionId : sessionId + jvmRoutePrefix;
        }
        return sessionId;
    }

    @Override
    public Session createEmptySession() {
        return new RedisSession(this);
    }

    /**
     * Adds a newly created session to both Redis and Tomcat's session manager (dual storage).
     * <p>All new sessions are saved to Redis with an appropriate TTL and added to Tomcat's local
     * session manager via {@link #save(Session)}, which calls {@link #setSessionExpiration(Session, long)}.</p>
     * <p><b>TTL Assignment (when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false, default):</b></p>
     * <ul>
     *     <li><b>Without DOT_CLUSTER_SESSION_ATTR:</b> Redis TTL = {@code undefinedSessionTypeTimeout}
     *     (default 15s). Used for cluster coordination during authentication. Tomcat manages expiration
     *     via {@code processExpires()}.</li>
     *     <li><b>With DOT_CLUSTER_SESSION_ATTR:</b> Redis TTL = {@code userSessionTimeout} (default 1800s).
     *     Redis manages expiration for cluster-consistent behavior.</li>
     * </ul>
     * <p><b>When TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true:</b> All sessions use {@code userSessionTimeout}
     * and Redis manages expiration.</p>
     *
     * @param session The session to add.
     * @throws RuntimeException if an error occurs while saving the session to Redis.
     */
    @Override
    public void add(final Session session) {
        try {
            this.save(session);
        } catch (final IOException ex) {
            final String errorMsg = String.format("Unable to add session [ %s ] to Redis: %s" ,session, ex.getMessage());
            log.error(errorMsg);
            throw new RuntimeException(errorMsg, ex);
        }
    }

    /**
     * Finds a session by ID using a multi-tier lookup strategy with stale session detection.
     * <p><b>Lookup Order:</b></p>
     * <ol>
     *     <li><b>ThreadLocal:</b> Check if this is the current request's session (fastest)</li>
     *     <li><b>Redis:</b> Deserialize from Redis if found</li>
     *     <li><b>Tomcat:</b> Check Tomcat's local session manager if not in Redis</li>
     *     <li><b>Not found:</b> Return null</li>
     * </ol>
     * <p><b>Stale Session Detection:</b></p>
     * <p>When a session is found in Tomcat but NOT in Redis, this method checks if it should have
     * been in Redis:</p>
     * <ul>
     *     <li><b>Has DOT_CLUSTER_SESSION_ATTR:</b> This is an authenticated session that SHOULD be
     *     in Redis. Not being in Redis means it expired there (TTL reached). The method expires
     *     the Tomcat copy and returns {@code null} to maintain consistency.</li>
     *     <li><b>No DOT_CLUSTER_SESSION_ATTR (when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false):</b>
     *     This is an undefined session managed by Tomcat. Redis TTL expired (15s), but session continues
     *     in Tomcat - normal case, return the session.</li>
     * </ul>
     * <p><b>Note:</b> When {@code TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true}, all sessions should
     * be in Redis, so finding a session only in Tomcat would trigger stale session detection regardless
     * of the attribute.</p>
     *
     * @param id The session identifier.
     * @return The session if found and valid, or {@code null} if not found or stale.
     * @throws IOException If an error occurs deserializing the session from Redis.
     */
    @Override
    public Session findSession(final String id) throws IOException {
        RedisSession session = null;
        log.debug(String.format("Trying to find session with ID = %s", id));
        if (null == id) {
            currentSessionIsPersisted.set(false);
            currentSession.remove();
            currentSessionSerializationMetadata.remove();
            currentSessionId.remove();
        } else if (id.equals(currentSessionId.get())) {
            session = currentSession.get();
        } else {
            final byte[] data = this.getRedisEntry(id);
            if (data != null) {
                log.debug(String.format("Session [ %s ] was found in Redis", id));
                final DeserializedSessionContainer container = this.sessionFromSerializedData(id, data);
                session = container.session;
                currentSession.set(session);
                currentSessionSerializationMetadata.set(container.metadata);
                currentSessionIsPersisted.set(true);
                currentSessionId.set(id);
            } else if (null != super.findSession(id)) {
                // Session found in Tomcat but not in Redis
                log.debug(String.format("Session [ %s ] was found in Tomcat but not in Redis", id));
                session = (RedisSession) super.findSession(id);

                // Check if the session is still valid before accessing attributes
                if (!session.isValid()) {
                    log.debug(String.format("Session [ %s ] found in Tomcat is already invalid. Returning null.", id));
                    session = null;
                    currentSessionIsPersisted.set(false);
                    currentSession.remove();
                    currentSessionSerializationMetadata.remove();
                    currentSessionId.remove();
                } else if (session.getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR) != null) {
                    // This is an authenticated session that SHOULD be in Redis but isn't
                    // This means it was invalidated/expired in Redis (TTL expired or explicitly deleted)
                    // We should expire it in Tomcat as well to maintain consistency
                    log.debug(String.format("Session [ %s ] has DOT_CLUSTER_SESSION_ATTR but is not in Redis. " +
                            "Assuming it was invalidated in Redis. Expiring session in Tomcat.", id));
                    try {
                        session.expire();
                    } catch (Exception e) {
                        log.error(String.format("Error expiring stale session [ %s ]: %s", id, e.getMessage()));
                    }
                    // Return null to indicate session is gone
                    session = null;
                    currentSessionIsPersisted.set(false);
                    currentSession.remove();
                    currentSessionSerializationMetadata.remove();
                    currentSessionId.remove();
                } else {
                    // This is an undefined/anonymous session managed by Tomcat - normal case
                    log.debug(String.format("Session [ %s ] is a Tomcat-managed session (no DOT_CLUSTER_SESSION_ATTR)", id));
                    currentSession.set(session);
                    currentSessionId.set(id);
                    currentSessionIsPersisted.set(false);
                    currentSessionSerializationMetadata.set(new SessionSerializationMetadata());
                }
            } else {
                currentSessionIsPersisted.set(false);
                currentSession.remove();
                currentSessionSerializationMetadata.remove();
                currentSessionId.remove();
            }
        }
        return session;
    }

    /**
     * De-serializes a specific Session that is being retrieved from Redis.
     *
     * @param id   The ID of the Session to deserialize.
     * @param data The data representing the serialized Session.
     *
     * @return The de-serialized Session object in the form of a {@link DeserializedSessionContainer} object.
     *
     * @throws IOException An error occurred when de-serializing the Session.
     */
    protected DeserializedSessionContainer sessionFromSerializedData(final String id, final byte[] data) throws IOException {
        log.debug(String.format("Deserializing session ID [ %s ] from Redis", id));
        if (Arrays.equals(NULL_SESSION, data)) {
            log.error(String.format("Encountered serialized Session ID [ %s ] with data equal to NULL_SESSION. This is a bug!", id));
            throw new IOException(String.format("Serialized data from Session ID [ %s ] is equal to NULL_SESSION", id));
        }
        RedisSession session;
        final SessionSerializationMetadata metadata = new SessionSerializationMetadata();
        try {
            session = (RedisSession) this.createEmptySession();
            this.serializer.deserializeInto(data, session, metadata);
            session.setId(id);
            session.setNew(false);
            session.setValid(true);
            // Update maxInactiveInterval based on session type:
            // - For authenticated sessions (Redis-managed): set to userSessionTimeout
            // - For undefined sessions (Tomcat-managed): keep Tomcat's default, don't override
            // This ensures authenticated sessions use the configured timeout while undefined
            // sessions continue using Tomcat's original inactive interval
            if (session.getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR) != null || this.isAnonTrafficEnabled) {
                session.setMaxInactiveInterval(this.userSessionTimeout);
            }
            // For undefined sessions, don't set maxInactiveInterval - keep Tomcat's default
            session.resetDirtyTracking();
            if (log.isTraceEnabled()) {
                log.trace(String.format("Contents from Session [ %s ]: ", id));
                final Enumeration<String> en = session.getAttributeNames();
                while (en.hasMoreElements()) {
                    log.trace("--> " + en.nextElement());
                }
            }
        } catch (final ClassNotFoundException ex) {
            final String errorMsg = String.format("Unable to deserialize data from session [ %s ]: %s", id, ex.getMessage());
            log.fatal(errorMsg);
            log.debug(ex);
            throw new IOException(errorMsg);
        }
        return new DeserializedSessionContainer(session, metadata);
    }

    /**
     * Saves the specified Session object to Redis.
     *
     * @param session The current {@link Session}.
     *
     * @throws IOException An error occurred when serializing the Session object.
     */
    public void save(final Session session) throws IOException {
        this.save(session, false);
    }

    /**
     * Saves the specified Session object to Redis.
     *
     * @param session   The current {@link Session}.
     * @param forceSave If the specified Session object MUST be saved no matter what, set this to {@code true}.
     *
     * @throws IOException An error occurred when serializing the Session object.
     */
    public void save(final Session session, final boolean forceSave) throws IOException {
        this.saveInternal(session, forceSave);
    }

    /**
     * Saves the specified Session object to Redis and adds it to Tomcat's session manager.
     * <p>The session data is persisted to Redis when any of the following conditions are met:</p>
     * <ol>
     *     <li>The {@code forceSave} parameter is set to {@code true}.</li>
     *     <li>The Session is dirty. That is, attributes were added and/or removed.</li>
     *     <li>The {@link ThreadLocal} variable that stores the persisted Session object is empty.</li>
     *     <li>The value of the {@link SessionSerializationMetadata} object contained in the
     *     {@link ThreadLocal} variable is different from the one in the specified {@code session} parameter.</li>
     * </ol>
     * <p><b>Dual Storage Strategy:</b></p>
     * <p>All sessions are stored in both Redis and Tomcat's session manager. The {@code DOT_CLUSTER_SESSION_ATTR}
     * attribute and {@code TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC} configuration determine the expiration mechanism:</p>
     * <ul>
     *     <li><b>When TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false (default):</b>
     *         <ul>
     *             <li><b>Without DOT_CLUSTER_SESSION_ATTR (undefined/anonymous sessions):</b> Redis stores with
     *             short TTL ({@code undefinedSessionTypeTimeout}, default 15s) for cluster coordination.
     *             Tomcat's {@code processExpires()} manages actual expiration based on {@code lastAccessedTime}.</li>
     *             <li><b>With DOT_CLUSTER_SESSION_ATTR (authenticated sessions):</b> Redis stores with full TTL
     *             ({@code userSessionTimeout}, default 1800s). Redis TTL manages expiration to ensure consistency
     *             across cluster nodes. Tomcat's {@code processExpires()} skips these sessions.</li>
     *         </ul>
     *     </li>
     *     <li><b>When TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true:</b> All sessions (including anonymous) use full
     *     TTL ({@code userSessionTimeout}) and Redis manages expiration. Tomcat's {@code processExpires()}
     *     only checks for sessions that expired in Redis but remain in Tomcat.</li>
     * </ul>
     * <p>This approach ensures authenticated sessions are clustered and expire consistently across nodes,
     * while undefined sessions use Redis temporarily for cluster coordination and then rely on local
     * Tomcat expiration (when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false).</p>
     *
     * @param session   The current {@link Session}.
     * @param forceSave If the specified Session object MUST be saved no matter what, set this to
     *                  {@code true}.
     *
     * @throws IOException An error occurred during the process of persisting the Session object.
     */
    protected void saveInternal(final Session session, final boolean forceSave) throws IOException {
        // Lock by session ID instead of on the whole manager so requests for different sessions can save in
        // parallel, while concurrent saves of the SAME session stay serialized to protect its read-modify-write
        // (the non-thread-safe changedAttributes map and dirty flag, plus the Redis write). We must key on the
        // ID rather than the Session object: findSession() deserializes a fresh RedisSession on every Redis hit,
        // so two requests for the same ID hold different objects and locking on the object would not serialize
        // them. The serializer and the Jedis pool are already thread-safe, so this is the only contention point
        // the previous method-level lock was actually guarding -- minus its node-wide serialization cost.
        final String sessionId = session.getId();
        final int stripe = Math.floorMod(null == sessionId ? 0 : sessionId.hashCode(), SAVE_LOCK_STRIPES);
        synchronized (this.saveLocks[stripe]) {
            this.doSaveInternal(session, forceSave);
        }
    }

    /**
     * Performs the actual save of the Session to Redis. Always invoked while holding the per-session monitor
     * acquired in {@link #saveInternal(Session, boolean)}; do not call directly.
     *
     * @param session   The current {@link Session}.
     * @param forceSave If the specified Session object MUST be saved no matter what, set this to {@code true}.
     *
     * @throws IOException An error occurred during the process of persisting the Session object.
     */
    private void doSaveInternal(final Session session, final boolean forceSave) throws IOException {
        log.debug(String.format("Saving session object [ %s ] to Redis server", session));
        final RedisSession redisSession = (RedisSession) session;
        final String sessionId = redisSession.getId();
        final boolean isCurrentSessionPersisted = null != this.currentSessionIsPersisted.get() && this.currentSessionIsPersisted.get();
        final SessionSerializationMetadata sessionSerializationMetadata = this.currentSessionSerializationMetadata.get();
        final byte[] originalSessionAttributesHash = null != sessionSerializationMetadata
                ? sessionSerializationMetadata.getSessionAttributesHash()
                : new byte[0];
        try {
            byte[] newSessionAttributesHash = this.serializer.attributesHashFrom(redisSession);
            if (forceSave || redisSession.isDirty() || !isCurrentSessionPersisted
                    || !Arrays.equals(originalSessionAttributesHash, newSessionAttributesHash)) {
                log.debug(String.format("Save on Session [ %s ] was determined to be necessary", sessionId));
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Contents from Session [ %s ]:", sessionId));
                    final Enumeration<String> en = redisSession.getAttributeNames();
                    int idx = 1;
                    while (en.hasMoreElements()) {
                        final String attrName = en.nextElement();
                        log.debug(String.format("%d. [ %s ] %s = %s", idx, sessionId, attrName, redisSession.getAttribute(attrName)));
                        idx++;
                    }
                }
                if (null == newSessionAttributesHash) {
                    newSessionAttributesHash = this.serializer.attributesHashFrom(redisSession);
                }
                final SessionSerializationMetadata updatedSerializationMetadata = new SessionSerializationMetadata();
                updatedSerializationMetadata.setSessionAttributesHash(newSessionAttributesHash);
                this.addRedisEntry(sessionId, this.serializer.serializeFrom(redisSession, updatedSerializationMetadata));
                redisSession.resetDirtyTracking();
                this.currentSessionSerializationMetadata.set(updatedSerializationMetadata);
                this.currentSessionIsPersisted.set(true);
            } else {
                log.debug(String.format("Save on Session [ %s ] was NOT necessary", sessionId));
            }
            // Set Redis TTL based on session type
            if (null == ((RedisSession) session).getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR) && !this.isAnonTrafficEnabled) {
                // Undefined session (no authentication): short TTL in Redis, will be expired by Tomcat
                log.debug(String.format("Session [ %s ] is undefined. Setting Redis TTL to %d seconds. " +
                        "Session expiration will be managed by Tomcat.", sessionId, this.undefinedSessionTypeTimeout));
                this.setSessionExpiration(session, this.undefinedSessionTypeTimeout);
            } else {
                // Authenticated session or anonymous traffic enabled: full TTL, Redis manages expiration
                log.debug(String.format("Session [ %s ] is persistable. Setting Redis TTL to %d seconds. " +
                        "Session expiration will be managed by Redis.", sessionId, this.userSessionTimeout));
                this.setSessionExpiration(session, this.userSessionTimeout);
            }
        } catch (final IOException e) {
            log.error(String.format("An error occurred when serializing session [ %s ]: %s", sessionId, e.getMessage()));
            log.debug(e);
            throw e;
        }
    }

    /**
     * Sets the expiration time for a session in both Redis and Tomcat's session manager.
     * <p>All sessions are stored in both Redis (for cluster coordination) and Tomcat's local
     * manager (for expiration processing). The {@code DOT_CLUSTER_SESSION_ATTR} attribute
     * and {@code TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC} configuration determine which system manages expiration:</p>
     * <ul>
     *     <li><b>When TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false (default):</b>
     *         <ul>
     *             <li><b>Without DOT_CLUSTER_SESSION_ATTR (undefined sessions):</b> Short Redis TTL (15s, auto-expires in Redis),
     *             Tomcat's processExpires() handles actual expiration using Tomcat's default maxInactiveInterval.
     *             The session's maxInactiveInterval is NOT changed - it keeps using Tomcat's original timeout.</li>
     *             <li><b>With DOT_CLUSTER_SESSION_ATTR (authenticated sessions):</b> Full Redis TTL (1800s, Redis manages expiration),
     *             session's maxInactiveInterval is set to match Redis TTL. Tomcat's processExpires() only checks for stale sessions.</li>
     *         </ul>
     *     </li>
     *     <li><b>When TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true:</b> All sessions use full Redis TTL (1800s)
     *     and Redis manages expiration. Session's maxInactiveInterval is set to match Redis TTL.
     *     Tomcat's processExpires() only checks for stale sessions.</li>
     * </ul>
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix
     * the Redis key, allowing multiple clusters to share the same Redis instance.</p>
     *
     * @param session The {@link Session} object whose TTL is being set.
     * @param seconds The number of seconds after which the Session will expire in Redis.
     */
    protected void setSessionExpiration(final Session session, final long seconds) {
        final String prefixedKey = this.prefix + session.getId();

        // Always set Redis TTL
        this.jedisPool.expire(prefixedKey.getBytes(StandardCharsets.UTF_8), seconds);

        // Only set maxInactiveInterval for authenticated sessions (Redis-managed)
        // For undefined sessions (Tomcat-managed), keep Tomcat's original maxInactiveInterval
        final RedisSession redisSession = (RedisSession) session;
        if (redisSession.getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR) != null || this.isAnonTrafficEnabled) {
            // Authenticated session: synchronize maxInactiveInterval with Redis TTL
            session.setMaxInactiveInterval((int) seconds);
        }
        // For undefined sessions, don't modify maxInactiveInterval - keep Tomcat's default timeout

        // Add to Tomcat's session manager for local tracking and expiration processing
        super.add(session);
    }

    @Override
    public void remove(final Session session) {
        this.remove(session, false);
    }

    @Override
    public void remove(final Session session, final boolean update) {
        if (this.isSessionPersistable(session)) {
            log.debug(String.format("Removing session ID [ %s ]", session.getId()));
            this.deleteRedisEntry(session.getId());
        }
        super.remove(session, update);
    }

    /**
     * This method is called by the {@link RedisSessionHandlerValve} after any HTTP Request has been processed. It
     * takes care of saving the current Session -- if it's still valid -- or removing it in case it is not. It also
     * differentiates "non-persistable" sessions from "persistable" ones, and handles them accordingly.
     * <p>For valid sessions, this method:</p>
     * <ul>
     *     <li>Saves the session to Redis (if dirty or based on persistence policy)</li>
     *     <li>Refreshes the Redis TTL (happens always via setSessionExpiration())</li>
     * </ul>
     * <p>Note: Session lifecycle methods like {@code access()} and {@code endAccess()} are handled by
     * Tomcat's request processing infrastructure (CoyoteAdapter.service() → Request.recycle() →
     * Request.recycleSessionInfo()), not by this method.</p>
     */
    public void afterRequest() {
        final RedisSession redisSession = this.currentSession.get();
        if (null == redisSession) {
            return;
        }
        final String sessionId = redisSession.getId();
        try {
            if (redisSession.isValid()) {
                log.debug(String.format("Request has finished. Saving session [ %s ]", sessionId));
                // Save session to Redis (also refreshes TTL via setSessionExpiration())
                this.save(redisSession, this.getAlwaysSaveAfterRequest());
            } else {
                if (!this.isSessionPersistable(redisSession)) {
                    super.remove(redisSession);
                } else {
                    log.debug(String.format("HTTP Session has been invalidated. Removing session [ %s ]", sessionId));
                    this.deleteRedisEntry(redisSession.getId());
                }
            }
        } catch (final Exception e) {
            log.error(String.format("Error storing/removing 'afterRequest' session [ %s ]: %s", sessionId, e.getMessage()));
            log.info(e);
        } finally {
            this.currentSession.remove();
            this.currentSessionId.remove();
            this.currentSessionIsPersisted.remove();
            log.debug(String.format("Request has finished. Session removed from ThreadLocal: %s" , redisSession.getIdInternal()));
        }
    }

    /**
     * Processes session expiration handling two distinct cases:
     * <p><b>Case 1: Undefined/Anonymous Sessions (no DOT_CLUSTER_SESSION_ATTR):</b></p>
     * <ul>
     *     <li>When {@code TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = false}, these sessions are managed by Tomcat</li>
     *     <li>Expired based on {@code lastAccessedTime} and {@code maxInactiveInterval}</li>
     *     <li>Redis stores with short TTL (15s) for cluster coordination only</li>
     * </ul>
     * <p><b>Case 2: Authenticated Sessions (has DOT_CLUSTER_SESSION_ATTR) or All Sessions
     * (when TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC = true):</b></p>
     * <ul>
     *     <li>These sessions are managed by Redis TTL for cluster-consistent expiration</li>
     *     <li>This method checks if session exists in Redis using {@link #existsInRedis(String)}</li>
     *     <li>If session is in Tomcat but NOT in Redis → Redis TTL expired → expire in Tomcat</li>
     *     <li>This prevents memory leaks where sessions remain in Tomcat after Redis cleanup</li>
     * </ul>
     */
    @Override
    public void processExpires() {
        long timeNow = System.currentTimeMillis();
        Session[] sessions = findSessions();
        int expireHere = 0;

        if (log.isDebugEnabled()) {
            log.debug("Start expire sessions at " + timeNow + " sessioncount " + sessions.length);
        }

        for (Session session : sessions) {
            if (session instanceof RedisSession) {
                RedisSession redisSession = (RedisSession) session;

                // Check valid flag before accessing attributes to prevent IllegalStateException
                if (!redisSession.isValid()) {
                    // Session already invalid, skip it
                    continue;
                }

                if (redisSession.getAttribute(RedisSession.DOT_CLUSTER_SESSION_ATTR) == null
                        && !this.isAnonTrafficEnabled) {
                    // Case 1: Undefined session (Tomcat-managed expiration)
                    // Check expiration using real lastAccessedTime calculated from Redis TTL
                    if (!redisSession.isNew()) {
                        try {
                            // Get the real lastAccessedTime (calculated from Redis TTL)
                            final long lastAccessedTime = redisSession.getLastAccessedTime();
                            final int maxInactiveInterval = redisSession.getMaxInactiveInterval();

                            // Calculate idle time
                            final long timeIdle = (timeNow - lastAccessedTime) / 1000L;

                            // Check if session has exceeded maxInactiveInterval
                            // Note: validFlag already checked at line 906, so session is valid here
                            if (maxInactiveInterval > 0 && timeIdle >= maxInactiveInterval) {
                                expireHere++;
                                if (log.isDebugEnabled()) {
                                    log.debug(String.format("Session [ %s ] expired by Tomcat. Idle time: %d seconds, Max inactive: %d seconds",
                                            redisSession.getId(), timeIdle, maxInactiveInterval));
                                }
                                redisSession.expire();
                            }
                        } catch (Throwable t) {
                            log.error(String.format("Error expiring session [ %s ]: %s", redisSession.getId(), t.getMessage()));
                        }
                    }
                } else {
                    // Case 2: Authenticated session (Redis-managed) or all sessions when isAnonTrafficEnabled = true
                    // Check if session still exists in Redis
                    try {
                        if (!existsInRedis(redisSession.getId())) {
                            // Redis TTL expired, but session still in Tomcat → memory leak
                            // Expire it in Tomcat to clean up
                            expireHere++;
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("Session [ %s ] expired in Redis (TTL reached) but still in Tomcat. " +
                                        "Expiring in Tomcat to prevent memory leak.", redisSession.getId()));
                            }
                            redisSession.expire();
                        }
                    } catch (Throwable t) {
                        log.error(String.format("Error checking/expiring Redis-managed session [ %s ]: %s",
                                redisSession.getId(), t.getMessage()));
                    }
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("End expire sessions processing. Expired sessions: " + expireHere);
        }
    }

    /**
     * Initializes the configuration parameters required to establish the connection to the Redis server. This approach
     * allows users to set it up using the following priority order:
     * <ul>
     *     <li>Using Java Properties. If required, these can be passed down to the {@code $JAVA_OPTS} parameter in the
     *     dotCMS startup script.</li>
     *     <li>Using Environment Variables, which is usually the most common approach.</li>
     *     <li>Finally, defaults back to the properties specified in the {@code {TOMCAT_HOME}/conf/context.xml} file.
     *     For example:
     *     <pre>
     *     {@code
     *     <Valve className="com.dotcms.tomcat.redissessions.RedisSessionHandlerValve" />
     *     <Manager className="com.dotcms.tomcat.redissessions.RedisSessionManager"
     *      host="localhost" password="REDIS_PWD"
     *      sessionPersistPolicies="DEFAULT" />
     *      }
     *      </pre>
     *      Will configure this plugin to connect to a Redis server in your local environment, using password
     *      {@code REDIS_PWD}, and using the {@code DEFAULT} session persist policy.
     *     </li>
     * </ul>
     * Any other configuration parameter that is not defined via any of the above methods will be assigned a default
     * value in order to make the plugin work.
     */
    private void initializeConfigParams() {
        log.info("-> Loading configuration parameters...");
        this.host = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_HOST_PROPERTY, this.host);
        this.port = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PORT_PROPERTY, this.port);
        this.username = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_USERNAME_PROPERTY, this.username);
        this.password = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PASSWORD_PROPERTY, this.password);
        this.ssl = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SSL_ENABLED_PROPERTY, this.ssl);
        this.sentinelMaster = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SENTINEL_MASTER_PROPERTY, this.sentinelMaster);
        if (null != sentinelMaster && !sentinelMaster.isEmpty()) {
            final String sentinels = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SENTINELS_PROPERTY, null);
            if (null != sentinels && !sentinels.isEmpty()) {
                this.setSentinels(sentinels);
            }
        }
        this.database = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_DATABASE_PROPERTY, this.database);
        this.timeout = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_TIMEOUT_PROPERTY, this.timeout);
        this.userSessionTimeout = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_USER_SESSION_TIMEOUT_PROPERTY,
                this.getTomcatSessionTimeoutInSeconds());
        final String persistentPolicies = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PERSISTENT_POLICIES_PROPERTY, null);
        if (null != persistentPolicies && !persistentPolicies.isEmpty()) {
            this.setSessionPersistPolicies(persistentPolicies);
        }
        this.maxTotal = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MAX_CONNECTIONS_PROPERTY, this.maxTotal);
        this.maxIdle = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MAX_IDLE_CONNECTIONS_PROPERTY, this.maxIdle);
        this.minIdle = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MIN_IDLE_CONNECTIONS_PROPERTY, this.minIdle);
        this.prefix = ConfigUtil.getConfigProperty(ConfigUtil.DOTCMS_CLUSTER_ID_PROPERTY, this.prefix);
        // Append a delimiter after the cluster ID so keys from clusters with shared leading characters
        // (e.g. "prod" vs "prod2") cannot collide. Guard against double-appending if already present.
        if (null != this.prefix && !this.prefix.isEmpty() && !this.prefix.endsWith(PREFIX_DELIMITER)) {
            this.prefix = this.prefix + PREFIX_DELIMITER;
        }
        this.manualDirtyTrackingSupportEnabled = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MANUAL_DIRTY_TRACKING_SUPPORT_PROPERTY,
                RedisSession.manualDirtyTrackingSupportEnabled);
        RedisSession.setManualDirtyTrackingSupportEnabled(this.manualDirtyTrackingSupportEnabled);
        this.manualDirtyTrackingSupportAttr = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MANUAL_DIRTY_TRACKING_SUPPORT_ATTR_PROPERTY,
                RedisSession.manualDirtyTrackingAttributeKey);
        this.persistOnDemandEnabled = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PERSIST_ON_DEMAND_PROPERTY,
                RedisSession.persistOnDemandEnabled);
        this.persistOnDemandAttr = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PERSIST_ON_DEMAND_ATTR_PROPERTY,
                RedisSession.persistOnDemandAttributeKey);
        RedisSession.setManualDirtyTrackingAttributeKey(this.manualDirtyTrackingSupportAttr);
        RedisSession.setPersistOnDemandAttributeKey(this.persistOnDemandAttr);
        this.isAnonTrafficEnabled = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_ENABLED_FOR_ANON_TRAFFIC, this.isAnonTrafficEnabled);
        this.undefinedSessionTypeTimeout = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_UNDEFINED_SESSION_TYPE_TIMEOUT,
                this.undefinedSessionTypeTimeout);
        log.info("\n[✓] TOMCAT_REDIS_SESSION_HOST: " + this.getHost() +
                "\n[✓] TOMCAT_REDIS_SESSION_PORT: " + this.getPort() +
                "\n[✓] TOMCAT_REDIS_SESSION_USERNAME: " + (null == this.username || this.username.isEmpty()
                    ? "- Not Set -"
                    : "- Set -") +
                "\n[✓] TOMCAT_REDIS_SESSION_PASSWORD: " + (null == this.password || this.password.isEmpty()
                    ? "- Not Set -"
                    : "- Set -") +
                "\n[✓] TOMCAT_REDIS_SESSION_SSL_ENABLED: " + this.getSsl() +
                "\n[✓] TOMCAT_REDIS_SESSION_SENTINEL_MASTER: " + this.getSentinelMaster() +
                "\n[✓] TOMCAT_REDIS_SESSION_SENTINELS: " + this.getSentinels() +
                "\n[✓] TOMCAT_REDIS_SESSION_DATABASE: " + this.getDatabase() +
                "\n[✓] TOMCAT_REDIS_SESSION_TIMEOUT: " + this.getTimeout() +
                "\n[✓] TOMCAT_REDIS_USER_SESSION_TIMEOUT (defaults to Tomcat's Session Timeout): " + this.userSessionTimeout +
                "\n[✓] TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES: " + this.getSessionPersistPolicies() +
                "\n[✓] TOMCAT_REDIS_MANUAL_DIRTY_TRACKING_SUPPORT: " + this.manualDirtyTrackingSupportEnabled +
                "\n[✓] TOMCAT_REDIS_MANUAL_DIRTY_TRACKING_SUPPORT_ATTR: " + this.manualDirtyTrackingSupportAttr +
                "\n[✓] TOMCAT_REDIS_PERSIST_ON_DEMAND: " + this.persistOnDemandEnabled +
                "\n[✓] TOMCAT_REDIS_PERSIST_ON_DEMAND_ATTR: " + this.persistOnDemandAttr +
                "\n[✓] TOMCAT_REDIS_MAX_CONNECTIONS: " + this.maxTotal +
                "\n[✓] TOMCAT_REDIS_MAX_IDLE_CONNECTIONS: " + this.maxIdle +
                "\n[✓] TOMCAT_REDIS_MAX_IDLE_CONNECTIONS: " + this.minIdle +
                "\n[✓] TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC: " + this.isAnonTrafficEnabled +
                "\n[✓] TOMCAT_REDIS_UNDEFINED_SESSION_TYPE_TIMEOUT: " + this.undefinedSessionTypeTimeout +
                "\n[✓] DOT_DOTCMS_CLUSTER_ID (Redis Key Prefix): " + (null == this.prefix || this.prefix.isEmpty()
                    ? "- Not Set -"
                    : this.prefix) +
                "\n");
    }

    /**
     * Initializes the connection to the Redis Server based on the specified configuration parameters. An additional
     * "PING" call allows us to determine whether the connection was successfully established or not.
     *
     * @throws LifecycleException An error occurred when creating the Unified Jedis Pool.
     */
    private void initializeRedisConnection() throws LifecycleException {
        log.info("-> Initializing Redis connection...");
        try {
            jedisPool = null == this.username || this.username.isEmpty()
                    ? new JedisPooled(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getPassword(), getSsl())
                    : new JedisPooled(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getUsername(), getPassword(), getSsl());
            // Immediately check that the connection via Jedis can indeed be established
            jedisPool.ping();
            log.info("\n\n" +
                    "    Successful! Redis-based Tomcat Sessions will expire after " + this.userSessionTimeout + " seconds.\n ");
        } catch (final Exception e) {
            throw new LifecycleException("FATAL - Failed to connect to Redis. Please check that the server is available, and " +
                    "parameters such as the host, port, and username/password are correct.", e);
        }
    }

    /**
     * Initializes the serializer that will be used to serialize/deserialize the Session and its attributes to/from
     * Redis.
     *
     * @throws ClassNotFoundException    The serializer class could not be found.
     * @throws NoSuchMethodException     The declared constructor for the serializer class could not be found.
     * @throws InvocationTargetException Failed to create a new instance of the serializer class.
     * @throws InstantiationException    The serializer class represents an abstract class, an interface, an array
     *                                   class, a primitive type, or void; or if the class has no nullary constructor;
     *                                   or if the instantiation fails for some other reason.
     * @throws IllegalAccessException    The serializer class or its nullary constructor is not accessible.
     */
    private void initializeSerializer() throws ClassNotFoundException, NoSuchMethodException,
            InvocationTargetException, InstantiationException, IllegalAccessException {
        log.info(String.format("-> Initializing Java Serializer: '%s'", this.serializationStrategyClass));
        final Class<?> serializerClass = Class.forName(this.serializationStrategyClass);
        this.serializer = (Serializer) serializerClass.getDeclaredConstructor().newInstance();
        final Loader loader = null != getContext() ? getContext().getLoader() : null;
        final ClassLoader classLoader = null != loader ? loader.getClassLoader() : null;
        this.serializer.setClassLoader(classLoader);
    }

    /**
     * Returns the timeout value that is currently set in the Tomcat server. This value will be used to set the
     * appropriate expiration time on entries in the Redis server for every Session that is created. This way, there's
     * no need to implement the {@link ManagerBase#processExpires()} method as we'll relly on Redis to evict the entries
     * on its own.
     *
     * @return The current Tomcat Session timeout value in seconds.
     */
    protected int getTomcatSessionTimeoutInSeconds() {
        return getContext().getSessionTimeout() * 60;
    }

    /**
     * Saves the specified key and its value to Redis.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix
     * they key. Doing this will allow multiple clusters to share the same Redis Server for
     * different customer instances/clusters.</p>
     *
     * @param key   The key for the new entry.
     * @param value Its serialized value.
     */
    protected void addRedisEntry(final String key, final byte[] value) {
        final String prefixedKey = this.prefix + key;
        this.jedisPool.set(prefixedKey.getBytes(StandardCharsets.UTF_8), value);
    }

    /**
     * Retrieves the value for the specified key from Redis.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix
     * they key. Doing this will allow multiple clusters to share the same Redis Server for
     * different customer instances/clusters.</p>
     *
     * @param key The key for the existing entry.
     *
     * @return The byte array value mapped to the specified key.
     */
    protected byte[] getRedisEntry(final String key) {
        final String prefixedKey = this.prefix + key;
        return this.jedisPool.get(prefixedKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Checks if a session entry exists in Redis.
     * <p>This method is used by {@link #processExpires()} to detect sessions that have expired
     * in Redis (TTL reached) but still exist in Tomcat's session manager, allowing cleanup to
     * prevent memory leaks.</p>
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix
     * the key.</p>
     *
     * @param sessionId The session ID to check.
     * @return {@code true} if the session exists in Redis, {@code false} otherwise.
     */
    protected boolean existsInRedis(final String sessionId) {
        final String prefixedKey = this.prefix + sessionId;
        return this.jedisPool.exists(prefixedKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Gets the remaining TTL (time-to-live) in seconds for a session in Redis.
     *
     * <p>This method is used to calculate the real last access time for Tomcat-managed sessions
     * by comparing the original TTL with the remaining TTL. The difference represents the time
     * elapsed since the last access.</p>
     *
     * <p><b>Formula</b>: lastAccessedTime = currentTime - (originalTTL - remainingTTL)</p>
     *
     * @param sessionId The session ID to check.
     * @return The remaining TTL in seconds, or -1 if the key doesn't exist or has no TTL, or -2 if the key doesn't exist at all.
     */
    protected long getRemainingTTL(final String sessionId) {
        final String prefixedKey = this.prefix + sessionId;
        return this.jedisPool.ttl(prefixedKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Deletes the specified key from Redis.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param key The key for the existing entry.
     */
    protected void deleteRedisEntry(final String key) {
        final String prefixedKey = this.prefix + key;
        this.jedisPool.del(prefixedKey);
    }

    // The methods bellow allow you to set up the Connection Pool Config properties for the Redis Connection via the
    // "org.apache.commons.pool2.impl.GenericObjectPoolConfig" class. You can set them through the
    // "{TOMCAT_HOME}/conf/context.xml" file by simply adding them as attributes of the "Manager" element.
    //
    // For instance, if you want to set the "maxTotal" attribute, you'd add the "connectionPoolMaxTotal=111" attribute
    // to it. You just need to remove the word "set" from the method's name and use it as the attribute name.

    public int getConnectionPoolMaxTotal() {
        return this.connectionPoolConfig.getMaxTotal();
    }

    public void setConnectionPoolMaxTotal(int connectionPoolMaxTotal) {
        this.connectionPoolConfig.setMaxTotal(connectionPoolMaxTotal);
    }

    public int getConnectionPoolMaxIdle() {
        return this.connectionPoolConfig.getMaxIdle();
    }

    public void setConnectionPoolMaxIdle(int connectionPoolMaxIdle) {
        this.connectionPoolConfig.setMaxIdle(connectionPoolMaxIdle);
    }

    public int getConnectionPoolMinIdle() {
        return this.connectionPoolConfig.getMinIdle();
    }

    public void setConnectionPoolMinIdle(int connectionPoolMinIdle) {
        this.connectionPoolConfig.setMinIdle(connectionPoolMinIdle);
    }

    // The methods bellow allow you to set up the Base Object Pool Config properties for the Redis Connection via the
    // "org.apache.commons.pool2.impl.BaseObjectPoolConfig" class. You can set them through the
    // "{TOMCAT_HOME}/conf/context.xml" file by simply adding them as attributes of the "Manager" element.
    //
    // For instance, if you want to set the "MaxWaitMillis" attribute, you'd add the "maxWaitMillis=111" attribute to
    // it. You just need to remove the word "set" from the method's name and use it as the attribute name.

    public boolean getLifo() {
        return this.connectionPoolConfig.getLifo();
    }

    public void setLifo(boolean lifo) {
        this.connectionPoolConfig.setLifo(lifo);
    }

    public long getMaxWaitMillis() {
        return this.connectionPoolConfig.getMaxWaitDuration().toMillis();
    }

    public void setMaxWaitMillis(long maxWaitMillis) {
        this.connectionPoolConfig.setMaxWait(Duration.ofMillis(maxWaitMillis));
    }

    public long getMinEvictableIdleTimeMillis() {
        return this.connectionPoolConfig.getMinEvictableIdleDuration().toMillis();
    }

    public void setMinEvictableIdleTimeMillis(long minEvictableIdleTimeMillis) {
        this.connectionPoolConfig.setMinEvictableIdleTime(Duration.ofMillis(minEvictableIdleTimeMillis));
    }

    public long getSoftMinEvictableIdleTimeMillis() {
        return this.connectionPoolConfig.getSoftMinEvictableIdleDuration().toMillis();
    }

    public void setSoftMinEvictableIdleTimeMillis(long softMinEvictableIdleTimeMillis) {
        this.connectionPoolConfig.setSoftMinEvictableIdleTime(Duration.ofMillis(softMinEvictableIdleTimeMillis));
    }

    public int getNumTestsPerEvictionRun() {
        return this.connectionPoolConfig.getNumTestsPerEvictionRun();
    }

    public void setNumTestsPerEvictionRun(int numTestsPerEvictionRun) {
        this.connectionPoolConfig.setNumTestsPerEvictionRun(numTestsPerEvictionRun);
    }

    public boolean getTestOnCreate() {
        return this.connectionPoolConfig.getTestOnCreate();
    }

    public void setTestOnCreate(boolean testOnCreate) {
        this.connectionPoolConfig.setTestOnCreate(testOnCreate);
    }

    public boolean getTestOnBorrow() {
        return this.connectionPoolConfig.getTestOnBorrow();
    }

    public void setTestOnBorrow(boolean testOnBorrow) {
        this.connectionPoolConfig.setTestOnBorrow(testOnBorrow);
    }

    public boolean getTestOnReturn() {
        return this.connectionPoolConfig.getTestOnReturn();
    }

    public void setTestOnReturn(boolean testOnReturn) {
        this.connectionPoolConfig.setTestOnReturn(testOnReturn);
    }

    public boolean getTestWhileIdle() {
        return this.connectionPoolConfig.getTestWhileIdle();
    }

    public void setTestWhileIdle(boolean testWhileIdle) {
        this.connectionPoolConfig.setTestWhileIdle(testWhileIdle);
    }

    public long getTimeBetweenEvictionRunsMillis() {
        return this.connectionPoolConfig.getDurationBetweenEvictionRuns().toMillis();
    }

    public void setTimeBetweenEvictionRunsMillis(long timeBetweenEvictionRunsMillis) {
        this.connectionPoolConfig.setTimeBetweenEvictionRuns(Duration.ofMillis(timeBetweenEvictionRunsMillis));
    }

    public String getEvictionPolicyClassName() {
        return this.connectionPoolConfig.getEvictionPolicyClassName();
    }

    public void setEvictionPolicyClassName(String evictionPolicyClassName) {
        this.connectionPoolConfig.setEvictionPolicyClassName(evictionPolicyClassName);
    }

    public boolean getBlockWhenExhausted() {
        return this.connectionPoolConfig.getBlockWhenExhausted();
    }

    public void setBlockWhenExhausted(boolean blockWhenExhausted) {
        this.connectionPoolConfig.setBlockWhenExhausted(blockWhenExhausted);
    }

    public boolean getJmxEnabled() {
        return this.connectionPoolConfig.getJmxEnabled();
    }

    public void setJmxEnabled(boolean jmxEnabled) {
        this.connectionPoolConfig.setJmxEnabled(jmxEnabled);
    }

    public String getJmxNameBase() {
        return this.connectionPoolConfig.getJmxNameBase();
    }

    public void setJmxNameBase(String jmxNameBase) {
        this.connectionPoolConfig.setJmxNameBase(jmxNameBase);
    }

    public String getJmxNamePrefix() {
        return this.connectionPoolConfig.getJmxNamePrefix();
    }

    public void setJmxNamePrefix(String jmxNamePrefix) {
        this.connectionPoolConfig.setJmxNamePrefix(jmxNamePrefix);
    }

}

/**
 * Utility class used to provide a specific {@link RedisSession} object and its de-serialized metadata -- all the
 * attributes in the Session.
 */
class DeserializedSessionContainer {

    public final RedisSession session;
    public final SessionSerializationMetadata metadata;

    public DeserializedSessionContainer(final RedisSession session, final SessionSerializationMetadata metadata) {
        this.session = session;
        this.metadata = metadata;
    }

}
