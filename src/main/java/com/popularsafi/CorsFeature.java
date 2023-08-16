package com.popularsafi;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFeature implements Filter {
    public static final String ALLOWED_METHODS = "OPTIONS, GET, POST, PUT, DELETE, HEAD";
    public final static int MAX_AGE = 42 * 60 * 60;
    public final static String DEFAULT_ALLOWED_HEADERS = "*, X-Requested-With," +
            "Content-Type, Accept, Authorization,CSRF-Token, X-Requested-By, Authorization, Content-Length," +
            "Host, User-Agent, Accept-Encoding, Connection";
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
        response.setHeader("Access-Control-Allow-Headers", DEFAULT_ALLOWED_HEADERS);
        response.setHeader("Access-Control-Expose-Headers", DEFAULT_ALLOWED_HEADERS);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Max-Age", String.valueOf(MAX_AGE));
        chain.doFilter(req, res);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
