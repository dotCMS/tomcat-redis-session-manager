package com.dotcms.tomcat.redissessions;

import java.io.IOException;

/**
 * This class allows the Redis Session Manager plugin to serialize the contents of the dotCMS session into a byte array.
 * This way, it can be persisted to Redis without problems. In case a non-serializable object is added to the session,
 * an error message will be logged to the {@code dotcms.log} file indicating the name of such an attribute, and the ID
 * of the session that it was added to.
 */
public interface Serializer {

    /**
     * Sets the class loader that will be used to deserialize the session attributes.
     *
     * @param loader The provided {@link ClassLoader} instance.
     */
    void setClassLoader(final ClassLoader loader);

    /**
     * Takes the attributes that are present in the specified Redis Session, and transforms them into a byte array.
     *
     * @param session The current {@link RedisSession} instance.
     *
     * @return A byte array representing the Session attributes.
     *
     * @throws IOException An error occurred when transforming the attributes into a byte array.
     */
    byte[] attributesHashFrom(final RedisSession session) throws IOException;

    /**
     * Takes the hash byte array from the Session Serialization Metadata object and writes it into the specified Redis
     * Session object.
     *
     * @param session  The {@link RedisSession} instance that will contain the updated hash byte array.
     * @param metadata The {@link SessionSerializationMetadata} instance that contains the hash byte array.
     *
     * @return The byte array with the Session attributes.
     *
     * @throws IOException An error occurred when reading/writing the metadata.
     */
    byte[] serializeFrom(final RedisSession session, final SessionSerializationMetadata metadata) throws IOException;

    /**
     * Takes the serialized byte array and loads them into the specified Redis Session Serialization Metadata instances
     * so that the attributes can be properly read by the Session Manager.
     *
     * @param data     The byte array coming from Redis.
     * @param session  The {@link RedisSession} that will hold the incoming attributes.
     * @param metadata The {@link SessionSerializationMetadata} instance that will hold the byte array.
     *
     * @throws IOException            An error occurred when processing the byte array.
     * @throws ClassNotFoundException An error occurred when transforming the byte array into the expected class
     *                                instance.
     */
    void deserializeInto(final byte[] data, final RedisSession session, final SessionSerializationMetadata metadata) throws IOException, ClassNotFoundException;

}
