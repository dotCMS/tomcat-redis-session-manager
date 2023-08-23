package com.dotcms.tomcat.redissessions;

import org.apache.catalina.util.CustomObjectInputStream;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;

/**
 * Implementation class for the {@link Serializer} interface. This implementation uses the default Java serialization
 * mechanism. The Class Loader used by this deserializer is retrieved from the current context provided by the
 * {@link org.apache.catalina.session.ManagerBase} class.
 */
public class JavaSerializer implements Serializer {
    private ClassLoader loader;

    private final Log log = LogFactory.getLog(JavaSerializer.class);

    @Override
    public void setClassLoader(final ClassLoader loader) {
        this.loader = loader;
    }

    @Override
    public byte[] attributesHashFrom(final RedisSession session) throws IOException {
        final HashMap<String, Object> attributes = new HashMap<>();
        for (final Enumeration<String> enumerator = session.getAttributeNames(); enumerator.hasMoreElements();) {
            final String key = enumerator.nextElement();
            attributes.put(key, session.getAttribute(key));
        }
        byte[] serialized;
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream();
             final ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(bos))) {
            oos.writeUnshared(attributes);
            oos.flush();
            serialized = bos.toByteArray();
        }
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException e) {
            log.error("Unable to get MessageDigest instance for MD5 for session ID " + session.getId());
        }
        return digester.digest(serialized);
    }

    @Override
    public byte[] serializeFrom(final RedisSession session, final SessionSerializationMetadata metadata) throws IOException {
        byte[] serialized;
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream();
             final ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(bos))) {
            oos.writeObject(metadata);
            session.writeObjectData(oos);
            oos.flush();
            serialized = bos.toByteArray();
        }
        return serialized;
    }

    @Override
    public void deserializeInto(final byte[] data, final RedisSession session, final SessionSerializationMetadata metadata)
                    throws IOException, ClassNotFoundException {
        try (final BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(data));
             final ObjectInputStream ois = new CustomObjectInputStream(bis, loader)) {
            final SessionSerializationMetadata serializedMetadata = (SessionSerializationMetadata) ois.readObject();
            metadata.copyFieldsFrom(serializedMetadata);
            session.readObjectData(ois);
        }
    }

}
