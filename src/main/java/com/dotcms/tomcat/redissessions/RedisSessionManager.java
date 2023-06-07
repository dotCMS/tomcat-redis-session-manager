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
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * This Redis-Managed Tomcat Session implementation provides the session creation, saving, and loading functionality for
 * dotCMS. For clustered environments, Persisted Sessions allow the system the possibility to bring one of the nodes
 * down without affecting the current Sessions from one or more Users.
 * <p>This is because they're no longer stored in memory by Tomcat, but in Redis. So, requests from Users can seamlessly
 * bounce from one node of the cluster to another, without causing any issues. In case one of the nodes goes down, there
 * will be no service interruption.</p>
 */
public class RedisSessionManager extends ManagerBase implements Lifecycle {

    enum SessionPersistPolicy {
        DEFAULT, SAVE_ON_CHANGE, ALWAYS_SAVE_AFTER_REQUEST;

        static SessionPersistPolicy fromName(final String name) {
            for (final SessionPersistPolicy policy : SessionPersistPolicy.values()) {
                if (policy.name().equalsIgnoreCase(name)) {
                    return policy;
                }
            }
            return DEFAULT;
        }
    }

    protected byte[] NULL_SESSION = "null".getBytes();
    private final Log log = LogFactory.getLog(RedisSessionManager.class);
    protected String host = "localhost";
    protected int port = 6379;
    protected int database = 0;
    protected String password = null;
    protected int timeout = Protocol.DEFAULT_TIMEOUT;
    protected String sentinelMaster = null;
    Set<String> sentinelSet = null;
    protected int maxTotal = 128;
    protected int maxIdle = 100;
    protected int minIdle = 32;
    protected String prefix = "";
    protected boolean isAnonTrafficEnabled = false;
    protected UnifiedJedis jedisPool;
    protected ConnectionPoolConfig connectionPoolConfig = this.buildPoolConfig();
    protected boolean ssl = false;
    protected RedisSessionHandlerValve handlerValve;
    protected ThreadLocal<RedisSession> currentSession = new ThreadLocal<>();
    protected ThreadLocal<SessionSerializationMetadata> currentSessionSerializationMetadata =
                    new ThreadLocal<>();
    protected ThreadLocal<String> currentSessionId = new ThreadLocal<>();
    protected ThreadLocal<Boolean> currentSessionIsPersisted = new ThreadLocal<>();
    protected Serializer serializer;
    protected String serializationStrategyClass = "com.dotcms.tomcat.redissessions.JavaSerializer";
    protected EnumSet<SessionPersistPolicy> sessionPersistPoliciesSet = EnumSet.of(SessionPersistPolicy.DEFAULT);

    /**
     * Creates the Connection Pool Configuration object for the Redis connection.
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

    public void setSsl(boolean ssl) {
        this.ssl = ssl;
    }
    
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int getDatabase() {
        return database;
    }

    public void setDatabase(int database) {
        this.database = database;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setSerializationStrategyClass(String strategy) {
        this.serializationStrategyClass = strategy;
    }

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
        log.info("====================================");
        log.info("Redis-managed Tomcat Session plugin");
        log.info("====================================");
        boolean attachedToValve = false;
        for (final Valve valve : getContext().getPipeline().getValves()) {
            if (valve instanceof RedisSessionHandlerValve) {
                log.info(String.format("- Attaching '%s' to '%s'", RedisSessionManager.class.getName(), valve.getClass().getName()));
                this.handlerValve = (RedisSessionHandlerValve) valve;
                this.handlerValve.setRedisSessionManager(this);
                attachedToValve = true;
                break;
            }
        }
        if (!attachedToValve) {
            final String error = "Unable to attach to session handling valve. Sessions cannot be saved after the request without the valve starting properly.";
            log.fatal(error);
            throw new LifecycleException(error);
        }
        try {
            this.initializeSerializer();
        } catch (final ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            log.fatal("Unable to load Java serializer");
            log.debug(e);
            throw new LifecycleException(e);
        }
        log.info("- Initializing configuration parameters:");
        this.initializeConfigParams();
        log.info("- Initializing Redis connection");
        this.initializeRedisConnection();
        getContext().setDistributable(true);
        log.info("- Successful! Redis-managed Tomcat Sessions will expire after " + this.getTomcatSessionTimeoutInSeconds() + " seconds.");
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
        log.debug("Stopping");
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
            session.setMaxInactiveInterval(this.getTomcatSessionTimeoutInSeconds());
            session.setId(sessionId);
            session.tellNew();
        }
        currentSession.set(session);
        currentSessionId.set(sessionId);
        currentSessionIsPersisted.set(false);
        currentSessionSerializationMetadata.set(new SessionSerializationMetadata());
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
        if (null != session && null != ((RedisSession) session).getAttribute(RedisSession.DOT_CLUSTER_SESSION)) {
            persistable = (boolean) ((RedisSession) session).getAttribute(RedisSession.DOT_CLUSTER_SESSION);
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

    @Override
    public void add(final Session session) {
        try {
            if (this.isSessionPersistable(session)) {
                this.save(session);
            } else {
                super.add(session);
            }
        } catch (final IOException ex) {
            final String errorMsg = "Unable to add session [ " + session + " ] to Redis store: " + ex.getMessage();
            log.error(errorMsg);
            throw new RuntimeException(errorMsg, ex);
        }
    }

    @Override
    public Session findSession(final String id) throws IOException {
        RedisSession session = null;
        if (null == id) {
            currentSessionIsPersisted.set(false);
            currentSession.set(null);
            currentSessionSerializationMetadata.set(null);
            currentSessionId.set(null);
        } else if (id.equals(currentSessionId.get())) {
            session = currentSession.get();
        } else {
            final byte[] data = this.loadSessionDataFromRedis(id);
            if (data != null) {
                final DeserializedSessionContainer container = this.sessionFromSerializedData(id, data);
                session = container.session;
                currentSession.set(session);
                currentSessionSerializationMetadata.set(container.metadata);
                currentSessionIsPersisted.set(true);
                currentSessionId.set(id);
            } else if (!this.isAnonTrafficEnabled && null != super.findSession(id)) {
                session = (RedisSession) super.findSession(id);
                currentSession.set(session);
                currentSessionId.set(id);
                currentSessionIsPersisted.set(false);
                currentSessionSerializationMetadata.set(new SessionSerializationMetadata());
            } else {
                currentSessionIsPersisted.set(false);
                currentSession.set(null);
                currentSessionSerializationMetadata.set(null);
                currentSessionId.set(null);
            }
        }
        return session;
    }

    public int getSize() {
        return Long.valueOf(jedisPool.dbSize()).intValue();
    }

    public String[] keys() {
        final Set<String> keySet = jedisPool.keys("*");
        return keySet.toArray(new String[keySet.size()]);
    }

    /**
     * Loads a Session from Redis, using the specified Session ID.
     *
     * @param id The ID of the Session to load.
     *
     * @return The data representing the Session as a byte array, or null if no Session was found.
     */
    public byte[] loadSessionDataFromRedis(final String id) {
        log.debug("Attempting to load session " + id + " from Redis");
        final byte[] data = this.get(id);
        if (data == null) {
            log.debug("Session " + id + " not found in Redis");
        }
        return data;
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
    public DeserializedSessionContainer sessionFromSerializedData(final String id, final byte[] data) throws IOException {
        log.debug("Deserializing session with ID " + id + " from Redis");
        if (Arrays.equals(NULL_SESSION, data)) {
            log.error("Encountered serialized session ID " + id + " with data equal to NULL_SESSION. This is a bug.");
            throw new IOException("Serialized session data was equal to NULL_SESSION");
        }
        RedisSession session;
        final SessionSerializationMetadata metadata = new SessionSerializationMetadata();
        try {
            session = (RedisSession) this.createEmptySession();
            serializer.deserializeInto(data, session, metadata);
            session.setId(id);
            session.setNew(false);
            session.setMaxInactiveInterval(this.getTomcatSessionTimeoutInSeconds());
            session.access();
            session.setValid(true);
            session.resetDirtyTracking();
            if (log.isTraceEnabled()) {
                log.trace("Session Contents [" + id + "]: ");
                final Enumeration<String> en = session.getAttributeNames();
                while (en.hasMoreElements()) {
                    log.trace("  " + en.nextElement());
                }
            }
        } catch (final ClassNotFoundException ex) {
            final String errorMsg = "Unable to deserialize into session with ID: " + id + ": " + ex.getMessage();
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
     * Saves the specified Session object to Redis. Unless the {@code forceSave} parameter is set to {@code true}, this
     * method will inspect the values in the Session object and will only save to Redis if it's dirty, i.e., its
     * attributes have been changed.
     *
     * @param session   The current {@link Session}.
     * @param forceSave If the specified Session object MUST be saved no matter what, set this to {@code true}.
     *
     * @throws IOException An error occurred when serializing the Session object.
     */
    protected void saveInternal(final Session session, final boolean forceSave) throws IOException {
        String sessionId = null;
        try {
            log.debug("Saving session: " + session + " into Redis");
            final RedisSession redisSession = (RedisSession) session;
            sessionId = redisSession.getId();
            if (log.isTraceEnabled()) {
                log.trace("Contents from Session '" + sessionId + "': ");
                final Enumeration<String> en = redisSession.getAttributeNames();
                while (en.hasMoreElements()) {
                    log.trace("  " + en.nextElement());
                }
            }
            Boolean isCurrentSessionPersisted;
            final SessionSerializationMetadata sessionSerializationMetadata = currentSessionSerializationMetadata.get();
            final byte[] originalSessionAttributesHash = sessionSerializationMetadata.getSessionAttributesHash();
            byte[] sessionAttributesHash = null;
            if (forceSave || redisSession.isDirty() || null == (isCurrentSessionPersisted = this.currentSessionIsPersisted.get())
                            || !isCurrentSessionPersisted || !Arrays.equals(originalSessionAttributesHash,
                                            (sessionAttributesHash = serializer.attributesHashFrom(redisSession)))) {
                log.debug("Save was determined to be necessary");

                if (null == sessionAttributesHash) {
                    sessionAttributesHash = serializer.attributesHashFrom(redisSession);
                }

                final SessionSerializationMetadata updatedSerializationMetadata = new SessionSerializationMetadata();
                updatedSerializationMetadata.setSessionAttributesHash(sessionAttributesHash);
                this.set(sessionId, serializer.serializeFrom(redisSession, updatedSerializationMetadata));
                redisSession.resetDirtyTracking();
                currentSessionSerializationMetadata.set(updatedSerializationMetadata);
                currentSessionIsPersisted.set(true);
            } else {
                log.debug("Save was determined to be unnecessary");
            }
            log.debug("Setting expire timeout on session '" + sessionId + "' to " + this.getTomcatSessionTimeoutInSeconds() + " seconds");
            this.setSessionExpiration(sessionId);
        } catch (final IOException e) {
            log.error("An error occurred when saving Session '" + sessionId + "': " + e.getMessage());
            log.debug(e);
            throw e;
        }
    }

    /**
     * Sets the expiration time for the newly created Session, as this process will be completely handled by Redis. It
     * uses the exact same session timeout value configured in Tomcat.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param sessionId The ID of the Session whose TTL is being set.
     */
    private void setSessionExpiration(final String sessionId) {
        final String prefixedKey = this.prefix + sessionId;
        this.jedisPool.expire(prefixedKey.getBytes(), this.getTomcatSessionTimeoutInSeconds());
    }

    @Override
    public void remove(final Session session) {
        this.remove(session, false);
    }

    @Override
    public void remove(final Session session, final boolean update) {
        if (this.isSessionPersistable(session)) {
            log.debug("Removing session ID: " + session.getId());
            this.del(session.getId());
        }
        super.remove(session, update);
    }

    /**
     * This method is called by the {@link RedisSessionHandlerValve} after request has been processed. It takes care of
     * optionally saving the current Session -- if it's still valid -- or removing it in case it is not.
     */
    public void afterRequest() {
        final RedisSession redisSession = currentSession.get();
        if (!this.isSessionPersistable(redisSession)) {
            if (null != redisSession) {
                if (redisSession.isValid()) {
                    super.add(redisSession);
                } else {
                    super.remove(redisSession);
                    currentSession.remove();
                    currentSessionId.remove();
                    currentSessionIsPersisted.remove();
                }
            }
        } else {
            if (redisSession != null) {
                final String sessionId = redisSession.getId();
                try {
                    if (redisSession.isValid()) {
                        log.debug("Request with session completed, saving session: " + sessionId);
                        this.save(redisSession, getAlwaysSaveAfterRequest());
                    } else {
                        log.debug("HTTP Session has been invalidated, removing: " + sessionId);
                        this.remove(redisSession);
                    }
                } catch (final Exception e) {
                    log.error("Error storing/removing session '" + sessionId + "': " + e.getMessage());
                    log.debug(e);
                } finally {
                    currentSession.remove();
                    currentSessionId.remove();
                    currentSessionIsPersisted.remove();
                    log.debug("Session removed from ThreadLocal: " + redisSession.getIdInternal());
                }
            }
        }
    }

    /**
     * If anonymous sessions are NOT allowed into Redis -- i.e., are handled in memory by Tomcat -- then we need to
     * check and invalidate all front-end sessions that have expired, which is the default behavior.
     */
    @Override
    public void processExpires() {
        if (!this.isAnonTrafficEnabled) {
            super.processExpires();
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
        this.host = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_HOST_PROPERTY, this.host);
        this.port = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PORT_PROPERTY, this.port);
        this.password = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PASSWORD_PROPERTY, this.password);
        this.ssl = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SSL_ENABLED_PROPERTY, this.ssl);
        this.sentinelMaster = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SENTINEL_MASTER_PROPERTY, this.sentinelMaster);
        if (null != sentinelMaster && !sentinelMaster.isEmpty()) {
            final String sentinels = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_SENTINELS_PROPERTY, null);
            if (!sentinels.isEmpty()) {
                this.setSentinels(sentinels);
            }
        }
        this.database = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_DATABASE_PROPERTY, this.database);
        this.timeout = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_TIMEOUT_PROPERTY, this.timeout);
        final String persistentPolicies = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_PERSISTENT_POLICIES_PROPERTY, null);
        if (null != persistentPolicies && !persistentPolicies.isEmpty()) {
            this.setSessionPersistPolicies(persistentPolicies);
        }
        this.maxTotal = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MAX_CONNECTIONS_PROPERTY, this.maxTotal);
        this.maxIdle = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MAX_IDLE_CONNECTIONS_PROPERTY, this.maxIdle);
        this.minIdle = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_MIN_IDLE_CONNECTIONS_PROPERTY, this.minIdle);
        this.prefix = ConfigUtil.getConfigProperty(ConfigUtil.DOTCMS_CLUSTER_ID_PROPERTY, this.prefix);
        this.isAnonTrafficEnabled = ConfigUtil.getConfigProperty(ConfigUtil.REDIS_ENABLED_FOR_ANON_TRAFFIC, this.isAnonTrafficEnabled);
        log.info("-- TOMCAT_REDIS_SESSION_HOST: " + this.getHost());
        log.info("-- TOMCAT_REDIS_SESSION_PORT: " + this.getPort());
        log.info("-- TOMCAT_REDIS_SESSION_PASSWORD: " + (null == this.password || this.password.isEmpty() ? "- Not Set -" : "- Set -"));
        log.info("-- TOMCAT_REDIS_SESSION_SSL_ENABLED: " + this.getSsl());
        log.info("-- TOMCAT_REDIS_SESSION_SENTINEL_MASTER: " + this.getSentinelMaster());
        log.info("-- TOMCAT_REDIS_SESSION_SENTINELS: " + this.getSentinels());
        log.info("-- TOMCAT_REDIS_SESSION_DATABASE: " + this.getDatabase());
        log.info("-- TOMCAT_REDIS_SESSION_TIMEOUT: " + this.getTimeout());
        log.info("-- TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES: " + this.getSessionPersistPolicies());
        log.info("-- TOMCAT_REDIS_MAX_CONNECTIONS: " + this.maxTotal);
        log.info("-- TOMCAT_REDIS_MAX_IDLE_CONNECTIONS: " + this.maxIdle);
        log.info("-- TOMCAT_REDIS_MAX_IDLE_CONNECTIONS: " + this.minIdle);
        log.info("-- DOT_DOTCMS_CLUSTER_ID (Redis Key Prefix): " + this.prefix);
        log.info("-- TOMCAT_REDIS_ENABLED_FOR_ANON_TRAFFIC: " + this.isAnonTrafficEnabled);
    }

    /**
     * Initializes the connection to the Redis Server based on the specified configuration parameters. An additional
     * "PING" call allows us to determine whether the connection was successfully established or not.
     *
     * @throws LifecycleException An error occurred when creating the Unified Jedis Pool.
     */
    private void initializeRedisConnection() throws LifecycleException {
        try {
            jedisPool = new JedisPooled(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getPassword(),
                            getSsl());
            jedisPool.ping();
        } catch (final Exception e) {
            throw new LifecycleException("Error connecting to Redis", e);
        }
    }

    /**
     * Initializes the serializer that will be used to serialize/deserialize the Session objects to/from Redis.
     *
     * @throws ClassNotFoundException The serializer class could not be found.
     * @throws IllegalAccessException The serializer class or its nullary constructor is not accessible.
     * @throws InstantiationException The serializer class represents an abstract class, an interface, an array class,
     *                                a primitive type, or void; or if the class has no nullary constructor; or if
     *                                the instantiation fails for some other reason.
     */
    private void initializeSerializer() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        log.info("Attempting to use serializer: " + this.serializationStrategyClass);
        this.serializer = (Serializer) Class.forName(this.serializationStrategyClass).newInstance();
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
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param key   The key for the new entry.
     * @param value Its serialized value.
     */
    protected void set(final String key, final byte[] value) {
        final String prefixedKey = this.prefix + key;
        this.jedisPool.set(prefixedKey.getBytes(), value);
    }

    /**
     * Saves the specified key and its value to Redis <b>ONLY if it doesn't exist yet</b>. If it does, its value will
     * NOT be updated.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param key   The key for the new entry.
     * @param value Its serialized value.
     *
     * @return If the key has been set, returns 1. If the key already existed, returns 0.
     */
    protected Long setnx(final String key, final byte[] value) {
        final String prefixedKey = this.prefix + key;
        return this.jedisPool.setnx(prefixedKey.getBytes(), value);
    }

    /**
     * Retrieves the value for the specified key from Redis.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param key The key for the existing entry.
     *
     * @return The value mapped to the specified key.
     */
    protected byte[] get(final String key) {
        final String prefixedKey = this.prefix + key;
        return this.jedisPool.get(prefixedKey.getBytes());
    }

    /**
     * Deletes the specified key from Redis.
     * <p>If the value for the {@code DOT_DOTCMS_CLUSTER_ID} is specified, it'll be used to prefix they key. Doing this
     * will allow multiple clusters to share the same Session Redis Store.</p>
     *
     * @param key The key for the existing entry.
     */
    protected void del(final String key) {
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
        return this.connectionPoolConfig.getMaxWaitMillis();
    }

    public void setMaxWaitMillis(long maxWaitMillis) {
        this.connectionPoolConfig.setMaxWaitMillis(maxWaitMillis);
    }

    public long getMinEvictableIdleTimeMillis() {
        return this.connectionPoolConfig.getMinEvictableIdleTimeMillis();
    }

    public void setMinEvictableIdleTimeMillis(long minEvictableIdleTimeMillis) {
        this.connectionPoolConfig.setMinEvictableIdleTimeMillis(minEvictableIdleTimeMillis);
    }

    public long getSoftMinEvictableIdleTimeMillis() {
        return this.connectionPoolConfig.getSoftMinEvictableIdleTimeMillis();
    }

    public void setSoftMinEvictableIdleTimeMillis(long softMinEvictableIdleTimeMillis) {
        this.connectionPoolConfig.setSoftMinEvictableIdleTimeMillis(softMinEvictableIdleTimeMillis);
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
        return this.connectionPoolConfig.getTimeBetweenEvictionRunsMillis();
    }

    public void setTimeBetweenEvictionRunsMillis(long timeBetweenEvictionRunsMillis) {
        this.connectionPoolConfig.setTimeBetweenEvictionRunsMillis(timeBetweenEvictionRunsMillis);
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

    public DeserializedSessionContainer(RedisSession session, SessionSerializationMetadata metadata) {
        this.session = session;
        this.metadata = metadata;
    }

}
