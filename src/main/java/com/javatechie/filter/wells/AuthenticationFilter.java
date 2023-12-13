package com.javatechie.filter.wells;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;

/**
* This is Similar to Wells Implementation
* Not using here, just for note
* */
//@Component
public class AuthenticationFilter extends OncePerRequestFilter {

    public static final String SUB = "sub";
    public static final String CLIENT_ID = "client_id";
    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer";
    public static final String OPTIONS = "OPTIONS";
    public static final String ORIGIN = "Origin";
    public static final String SCOPE = "scope";
    public static final String HLFUS = "HLFUS";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);
    private static final TypeReference<HashMap<String, Object>> valueTypeRef = new TypeReference<>(){
    };

    @Autowired
    private RestTemplate restTemplate;

    @Value("")
    private String clientId;

    @Value("")
    private String pingUrl;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith(BEARER)) {
            String token = authHeader.substring(7);
            LOGGER.info(String.format("$$$ filter.dofilter token = %s.",token));
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add(CLIENT_ID, clientId);

            ResponseEntity<String> result = restTemplate.postForEntity(createPingRequest(token).toString(),requestBody, String.class);
            validateAndSetContext(request, response, result);

            filterChain.doFilter(request, response);

        } else {
            LOGGER.info("Throwing Unauthorized exception as there is no token in the header");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Unauthorized");
        }
    }

    private void validateAndSetContext(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, ResponseEntity<String> result) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        HashMap<String, Object> userInfo = mapper.readValue(result.getBody(), valueTypeRef);
        LOGGER.info(String.format("Ping request Response = %s.",userInfo));
        if (userInfo.get(SUB) == null || !userInfo.get(SCOPE).toString().contains(HLFUS)){ //validate token
            LOGGER.info("Throwing Unauthorized exception as the token is invalid");
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Unauthorized");
        }
        UserPrinciple userDetails = new UserPrinciple(userInfo.get(SUB)+"", httpServletRequest.getHeader("username"));
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private PingRequest createPingRequest(String token) {
        PingRequest pingRequest = new PingRequest();
        pingRequest.setToken(token);
        pingRequest.setUrl(pingUrl);
        return pingRequest;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest httpServletRequest) {
        return isPreflightRequest(httpServletRequest);
    }

    private boolean isPreflightRequest(HttpServletRequest httpServletRequest){
        boolean isActuatorURI = httpServletRequest.getRequestURI().contains("/actuator");
        boolean isCorsRequest = OPTIONS.equalsIgnoreCase(httpServletRequest.getMethod()) && httpServletRequest.getHeader(ORIGIN) != null;
        LOGGER.info("Is Request is Preflight: "+ (isActuatorURI || isCorsRequest));
        return isActuatorURI || isCorsRequest;
    }
}
