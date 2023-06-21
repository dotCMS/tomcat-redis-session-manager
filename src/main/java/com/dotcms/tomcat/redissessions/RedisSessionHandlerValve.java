package com.dotcms.tomcat.redissessions;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

import javax.servlet.ServletException;
import java.io.IOException;

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

    /**
     * Creates an instance of this Valve with the appropriate support for async operations.
     */
    public RedisSessionHandlerValve() {
        super(true);
    }

    public void setRedisSessionManager(RedisSessionManager manager) {
        this.manager = manager;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            getNext().invoke(request, response);
        } finally {
            manager.afterRequest();
        }
    }
}
