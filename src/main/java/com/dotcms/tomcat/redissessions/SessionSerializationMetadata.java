package com.dotcms.tomcat.redissessions;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;

/**
 * Stores and provides the hash of the Session attributes. An instance of this object is what gets stored in/read from
 * the Redis server.
 */
public class SessionSerializationMetadata implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Log log = LogFactory.getLog(SessionSerializationMetadata.class);

    private byte[] sessionAttributesHash;

    public SessionSerializationMetadata() {
        this.sessionAttributesHash = new byte[0];
    }

    public byte[] getSessionAttributesHash() {
        return this.sessionAttributesHash;
    }

    public void setSessionAttributesHash(final byte[] sessionAttributesHash) {
        this.sessionAttributesHash = sessionAttributesHash;
    }

    /**
     * Takes the available properties exposed by the Session Serialization Metadata object and copies them into this
     * instance.
     *
     * @param metadata The {@link SessionSerializationMetadata} instance whose values need to be read.
     */
    public void copyFieldsFrom(final SessionSerializationMetadata metadata) {
        this.setSessionAttributesHash(metadata.getSessionAttributesHash());
    }

    private void writeObject(final ObjectOutputStream out) throws Exception {
        try {
            out.writeInt(this.sessionAttributesHash.length);
            out.write(this.sessionAttributesHash);
        } catch (final Exception e) {
            log.error(e);
            throw e;
        }
    }

    private void readObject(final ObjectInputStream in) throws Exception {
        try {
            int hashLength = in.readInt();
            byte[] sessionAttributesHash = new byte[hashLength];
            in.read(sessionAttributesHash, 0, hashLength);
            this.sessionAttributesHash = sessionAttributesHash;
        } catch (final Exception e) {
            log.error(e);
            throw e;
        }
    }

    private void readObjectNoData() throws ObjectStreamException {
        this.sessionAttributesHash = new byte[0];
    }

}
