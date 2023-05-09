package com.orangefunction.tomcat.redissessions;

import com.orangefunction.tomcat.util.ConfigUtil;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Loader;
import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.session.ManagerBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisSentinelPool;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.util.Pool;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * This Redis-Managed Tomcat Session implementation provides the session creation, saving, and loading functionality.
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
    protected Pool<Jedis> connectionPool;
    protected JedisPoolConfig connectionPoolConfig = new JedisPoolConfig();
    protected boolean ssl = false;
    protected RedisSessionHandlerValve handlerValve;
    protected ThreadLocal<RedisSession> currentSession = new ThreadLocal<>();
    protected ThreadLocal<SessionSerializationMetadata> currentSessionSerializationMetadata =
                    new ThreadLocal<>();
    protected ThreadLocal<String> currentSessionId = new ThreadLocal<>();
    protected ThreadLocal<Boolean> currentSessionIsPersisted = new ThreadLocal<>();
    protected Serializer serializer;
    protected static String name = "RedisSessionManager";
    protected String serializationStrategyClass = "com.orangefunction.tomcat.redissessions.JavaSerializer";
    protected EnumSet<SessionPersistPolicy> sessionPersistPoliciesSet = EnumSet.of(SessionPersistPolicy.DEFAULT);

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

    public boolean getSaveOnChange() {
        return this.sessionPersistPoliciesSet.contains(SessionPersistPolicy.SAVE_ON_CHANGE);
    }

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

    protected Jedis acquireConnection() {
        final Jedis jedis = connectionPool.getResource();
        if (this.getDatabase() != 0) {
            jedis.select(this.getDatabase());
        }
        return jedis;
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
            log.fatal("Unable to load Java serializer", e);
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
        if (log.isDebugEnabled()) {
            log.debug("Stopping");
        }
        setState(LifecycleState.STOPPING);
        try {
            connectionPool.destroy();
        } catch (Exception e) {
            // Do nothing.
        }
        // Require a new random number generator if we are restarted
        super.stopInternal();
    }

    @Override
    public Session createSession(String requestedSessionId) {
        RedisSession session = null;
        String sessionId;
        final String jvmRoute = this.getJvmRoute();

        try (final Jedis jedis = this.acquireConnection()) {
            // Ensure generation of a unique session identifier.
            if (null != requestedSessionId) {
                sessionId = this.sessionIdWithJvmRoute(requestedSessionId, jvmRoute);
                if (jedis.setnx(sessionId.getBytes(), NULL_SESSION) == 0L) {
                    sessionId = null;
                }
            } else {
                do {
                    sessionId = this.sessionIdWithJvmRoute(generateSessionId(), jvmRoute);
                } while (jedis.setnx(sessionId.getBytes(), NULL_SESSION) == 0L); // 1 = key set; 0 = key already existed
            }
            /*
             * Even though the key is set in Redis, we are not going to flag the current thread as having had
             * the session persisted since the session isn't actually serialized to Redis yet. This ensures that
             * the save(session) at the end of the request will serialize the session into Redis with 'set'
             * instead of 'setnx'.
             */
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
            if (null != session) {
                try {
                    this.saveInternal(jedis, session, true);
                } catch (final IOException ex) {
                    log.error("Error saving newly created session with ID " + requestedSessionId + ": " + ex.getMessage(), ex);
                    currentSession.set(null);
                    currentSessionId.set(null);
                    session = null;
                }
            }
        }
        return session;
    }

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
            save(session);
        } catch (final IOException ex) {
            final String errorMsg = "Unable to add to session [ " + session + " ] manager store: " + ex.getMessage();
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
            } else {
                currentSessionIsPersisted.set(false);
                currentSession.set(null);
                currentSessionSerializationMetadata.set(null);
                currentSessionId.set(null);
            }
        }
        return session;
    }

    public void clear() {
        try (final Jedis jedis = this.acquireConnection()) {
            jedis.flushDB();
        }
    }

    public int getSize() {
        try (final Jedis jedis = this.acquireConnection()) {
            return Long.valueOf(jedis.dbSize()).intValue();
        }
    }

    public String[] keys() {
        try (final Jedis jedis = this.acquireConnection()) {
            final Set<String> keySet = jedis.keys("*");
            return keySet.toArray(new String[keySet.size()]);
        }
    }

    public byte[] loadSessionDataFromRedis(final String id) {
        try (final Jedis jedis = this.acquireConnection()) {
            log.debug("Attempting to load session " + id + " from Redis");
            final byte[] data = jedis.get(id.getBytes());
            if (data == null) {
                log.debug("Session " + id + " not found in Redis");
            }
            return data;
        }
    }

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
            final String errorMsg = "Unable to deserialize into session with ID: " + id;
            log.fatal(errorMsg, ex);
            throw new IOException(errorMsg, ex);
        }
        return new DeserializedSessionContainer(session, metadata);
    }

    public void save(final Session session) throws IOException {
        this.save(session, false);
    }

    public void save(final Session session, final boolean forceSave) throws IOException {
        try (final Jedis jedis = this.acquireConnection()) {
            this.saveInternal(jedis, session, forceSave);
        }
    }

    protected boolean saveInternal(final Jedis jedis, final Session session, final boolean forceSave) throws IOException {
        boolean error = true;
        try {
            log.debug("Saving session " + session + " into Redis");
            final RedisSession redisSession = (RedisSession) session;
            if (log.isTraceEnabled()) {
                log.trace("Session Contents [" + redisSession.getId() + "]: ");
                final Enumeration<String> en = redisSession.getAttributeNames();
                while (en.hasMoreElements()) {
                    log.trace("  " + en.nextElement());
                }
            }
            final byte[] binaryId = redisSession.getId().getBytes();
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
                jedis.set(binaryId, serializer.serializeFrom(redisSession, updatedSerializationMetadata));
                redisSession.resetDirtyTracking();
                currentSessionSerializationMetadata.set(updatedSerializationMetadata);
                currentSessionIsPersisted.set(true);
            } else {
                log.debug("Save was determined to be unnecessary");
            }
            log.debug("Setting expire timeout on session [" + redisSession.getId() + "] to " + this.getTomcatSessionTimeoutInSeconds() + " seconds");
            jedis.expire(binaryId, this.getTomcatSessionTimeoutInSeconds());
            return false;
        } catch (final IOException e) {
            log.error("An error occurred when saving Session " + session + ": " + e.getMessage(), e);
            throw e;
        } finally {
            return error;
        }
    }

    @Override
    public void remove(Session session) {
        remove(session, false);
    }

    @Override
    public void remove(Session session, boolean update) {
        log.debug("Removing session ID: " + session.getId());
        try (final Jedis jedis = acquireConnection()) {
            jedis.del(session.getId());
        }
    }

    public void afterRequest() {
        final RedisSession redisSession = currentSession.get();
        if (redisSession != null) {
            try {
                if (redisSession.isValid()) {
                    log.debug("Request with session completed, saving session: " + redisSession.getId());
                    this.save(redisSession, getAlwaysSaveAfterRequest());
                } else {
                    log.debug("HTTP Session has been invalidated, removing: " + redisSession.getId());
                    this.remove(redisSession);
                }
            } catch (final Exception e) {
                log.error("Error storing/removing session: " + redisSession.getId(), e);
            } finally {
                currentSession.remove();
                currentSessionId.remove();
                currentSessionIsPersisted.remove();
                log.debug("Session removed from ThreadLocal: " + redisSession.getIdInternal());
            }
        }
    }

    @Override
    public void processExpires() {
        // We are going to use Redis's ability to expire keys for session expiration.
        // Do nothing.
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
     *     <Valve className="com.orangefunction.tomcat.redissessions.RedisSessionHandlerValve" />
     *     <Manager className="com.orangefunction.tomcat.redissessions.RedisSessionManager"
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
        log.info("-- TOMCAT_REDIS_SESSION_HOST: " + this.getHost());
        log.info("-- TOMCAT_REDIS_SESSION_PORT: " + this.getPort());
        log.info("-- TOMCAT_REDIS_SESSION_PASSWORD: " + (null == this.password || this.password.isEmpty() ? "Not Set" : "Set"));
        log.info("-- TOMCAT_REDIS_SESSION_SSL_ENABLED: " + this.getSsl());
        log.info("-- TOMCAT_REDIS_SESSION_SENTINEL_MASTER: " + this.getSentinelMaster());
        log.info("-- TOMCAT_REDIS_SESSION_SENTINELS: " + this.getSentinels());
        log.info("-- TOMCAT_REDIS_SESSION_DATABASE: " + this.getDatabase());
        log.info("-- TOMCAT_REDIS_SESSION_TIMEOUT: " + this.getTimeout());
        log.info("-- TOMCAT_REDIS_SESSION_PERSISTENT_POLICIES: " + this.getSessionPersistPolicies());
    }

    private void initializeRedisConnection() throws LifecycleException {
        try {
            if (getSentinelMaster() != null) {
                final Set<String> sentinelSet = getSentinelSet();
                if (sentinelSet != null && sentinelSet.size() > 0) {
                    connectionPool = new JedisSentinelPool(getSentinelMaster(), sentinelSet, this.connectionPoolConfig,
                                    getTimeout(), getPassword());
                } else {
                    throw new LifecycleException(
                                    "Error configuring Redis Sentinel connection pool: Expected both `sentinelMaster` and `sentinels` properties to be configured");
                }
            } else if (getSsl()) {
                connectionPool = new JedisPool(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getPassword(),
                                getSsl());
            } else {
                connectionPool = new JedisPool(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getPassword());
            }
        } catch (final Exception e) {
            throw new LifecycleException("Error connecting to Redis", e);
        }
    }

    private void initializeSerializer() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        log.info("Attempting to use serializer: " + serializationStrategyClass);
        serializer = (Serializer) Class.forName(serializationStrategyClass).newInstance();
        Loader loader = null;
        if (getContext() != null) {
            loader = getContext().getLoader();
        }
        ClassLoader classLoader = null;
        if (loader != null) {
            classLoader = loader.getClassLoader();
        }
        serializer.setClassLoader(classLoader);
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

    // Connection Pool Config Accessors
    // - from org.apache.commons.pool2.impl.GenericObjectPoolConfig

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

    // - from org.apache.commons.pool2.impl.BaseObjectPoolConfig

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

class DeserializedSessionContainer {
    public final RedisSession session;
    public final SessionSerializationMetadata metadata;

    public DeserializedSessionContainer(RedisSession session, SessionSerializationMetadata metadata) {
        this.session = session;
        this.metadata = metadata;
    }

}
