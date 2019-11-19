package org.camunda.bpm.extension.keycloak.showcase.filter;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.util.EngineUtil;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.servlet.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatelessUserAuthenticationFilter implements Filter {

    static Logger log = LoggerFactory.getLogger(StatelessUserAuthenticationFilter.class);

    @Override
    public void init(FilterConfig filterConfig) {

        log.info("Init StatelessUserAuthenticationFilter");

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // Current limitation: Only works for the default engine
        ProcessEngine engine = EngineUtil.lookupProcessEngine("default");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String username = null;

        //log.info(SecurityContextHolder.getContext().getAuthentication().getClaims().toString());

        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else if (principal instanceof Jwt){

        	Jwt token = (Jwt) principal;

        	log.info("token {}",token.getClaims().toString());

        }
        else {
            username = principal.toString();
        }

        username = "bla";
        log.info("filter for user {}",username);
        try {
            engine.getIdentityService().setAuthentication(username, getUserGroups(username));


            chain.doFilter(request, response);
        } finally {
            clearAuthentication(engine);
        }

    }

    @Override
    public void destroy() {

    }

    private void clearAuthentication(ProcessEngine engine) {
        engine.getIdentityService().clearAuthentication();
    }

    private List<String> getUserGroups(String userId){

        List<String> groupIds = new ArrayList<String>();

        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        groupIds = authentication.getAuthorities().stream()
                .map(res -> res.getAuthority())
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());

        groupIds.add("task-reader");
        log.info("groups{}",groupIds.toString());
        return groupIds;

    }

}