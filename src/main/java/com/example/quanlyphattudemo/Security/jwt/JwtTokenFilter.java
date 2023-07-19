package com.example.quanlyphattudemo.Security.jwt;


import com.example.quanlyphattudemo.Services.PhatTusServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// class co trach nhiem goi nhung clas nhỏ
// @RequiredArgsConstructor // tam thoi thay the autowired phair co final
public class JwtTokenFilter extends OncePerRequestFilter  {
    private static Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);
    @Autowired
    private PhatTusServices userSevice;
    @Autowired
    private  JwtProvider jwtProvider;
    @Autowired
    private  UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwtToken = getTokenFromRequest(request);
            if (jwtToken != null && jwtProvider.validateToken(jwtToken)){
                String username = jwtProvider.getUserNameFromToken(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                if (userDetails != null){

                    // xác định kiểu
                    // phương thúc tạo ra 1 authentication mới chứa thông tin người dùng và quyền truy cập tài nguyên
                    // su dung username va pass de authentication
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,// ma xac nhan
                                    userDetails.getAuthorities() //.getAuthorities() danh sách quền hạn của người dùng
                            );
                    // cho phep thong báo request da co nguoi authen vào
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request));
                   // luu tru thong tin vào contex cho đợt sau
                    //thiết lập authentication mới tạo vào context của srping security và cho phép người dùng truy cập các dữ liệu đợc bảo vệ
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        } catch (Exception e) {
            logger.error("Failed - > Unauthenticated Message {}", e.getMessage());
        }
        filterChain.doFilter(request,response);
    }

    // lay token tu http reques
    private String getTokenFromRequest(HttpServletRequest request) {
        // token dc chua o header
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header)  && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }


}
