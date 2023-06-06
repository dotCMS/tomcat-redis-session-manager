package com.dotcms.tomcat.redissessions;

import java.io.IOException;
import javax.servlet.ServletException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/**
 * This valve is responsible for making sure that the {@link RedisSessionManager#afterRequest()} method is called. The
 * session manager will save the current Session in Redis depending on different circumstances, for instance:
 * <ul>
 *     <li>The selected persistence is set to saving the Session after every request.</li>
 *     <li>The current session is "dirty".</li>
 *     <li>There's no record of a previous persisted session.</li>
 *     <li>The attributes of the current session don't match the ones of the session that is being tracked.</li>
 * </ul>
 */
public class RedisSessionHandlerValve extends ValveBase {

    private RedisSessionManager manager;
    private Request currentRequest;

    /**
     * Creates an instance of this Valve with the appropriate support for async operations.
     */
    public RedisSessionHandlerValve() {
        super(true);
    }

    public void setRedisSessionManager(RedisSessionManager manager) {
        this.manager = manager;
    }

    /**
     * Takes the current instance of the {@link Request} object so that the underlying {@link RedisSessionManager} can
     * access it and interact with its data.
     *
     * @return The current {@link Request} object.
     */
    public Request getCurrentRequest() {
        return this.currentRequest;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        this.currentRequest = request;
        try {
            getNext().invoke(request, response);
        } finally {
            manager.afterRequest();
        }
    }
}
