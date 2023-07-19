package com.example.quanlyphattudemo.Security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// tieeps nhan de loi tra ve
// AuthenticationEntryPoint hứng lỗi exception đầu cuối trong quá trình security hd
@Component
public class JwtEntryPoin implements AuthenticationEntryPoint {
    public static Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    // tra lỗi về htong -cliend
    // SC_UNAUTHORIZED mã 403
    @Override

    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException  {
        logger.error("Failed -> Unauthenticated Message {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Failed -> Unauthenticated");
    }
}
