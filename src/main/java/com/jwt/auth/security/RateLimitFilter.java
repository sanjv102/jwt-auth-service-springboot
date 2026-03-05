package com.jwt.auth.security;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt.auth.audit.AuditEventType;
import com.jwt.auth.ratelimit.RateLimitPolicies;
import com.jwt.auth.ratelimit.RateLimitService;
import com.jwt.auth.response.ApiResponse;
import com.jwt.auth.service.AuditLogService;
import com.jwt.auth.util.RequestContext;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tools.jackson.databind.ObjectMapper;

@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter{

	private final RateLimitService rateLimitService;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws IOException, ServletException {

        String path = request.getRequestURI();
        String ip = request.getRemoteAddr();

        RequestContext.setIp(ip);

        try {
            boolean allowed = true;

            if (path.startsWith("/api/auth/login")) {
                allowed = rateLimitService.isAllowed(
                        "LOGIN:" + ip,
                        RateLimitPolicies.LOGIN
                );
            }
            else if (path.startsWith("/api/auth/register")) {
                allowed = rateLimitService.isAllowed(
                        "REGISTER:" + ip,
                        RateLimitPolicies.REGISTER
                );
            }
            else if (path.startsWith("/api/auth/forgot-password")) {
                allowed = rateLimitService.isAllowed(
                        "FORGOT:" + ip,
                        RateLimitPolicies.FORGOT_PASSWORD
                );
            }

            if (!allowed) {
                auditLogService.log(
                        AuditEventType.RATE_LIMIT_BLOCKED,
                        null,
                        ip,
                        path,
                        false
                );

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(
                        objectMapper.writeValueAsString(
                                new ApiResponse<>(false, "Too many requests. Try again later", null)
                        )
                );
                return;
            }

            filterChain.doFilter(request, response);

        } finally {
            RequestContext.clear();
        }
    }
	
}
