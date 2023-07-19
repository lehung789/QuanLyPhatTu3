package com.example.quanlyphattudemo.config;


import com.example.quanlyphattudemo.Security.jwt.JwtEntryPoin;
import com.example.quanlyphattudemo.Security.jwt.JwtTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration // chua cac bean
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
// WebSecurityConfigurerAdapter chua pthuc lm nhung gi
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private  final UserDetailsService userDetailsService;
    private final JwtEntryPoin jwtEntryPoin;
    @Bean
    public JwtTokenFilter jwtTokenFilter(){
        return new JwtTokenFilter();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    // cấu hình security
//    userDetailsService hung username
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
// khoi taobean dung cho login khoi tao authen hethong
    @Bean //tu dong khoi tao tu dong chay dau tien
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    // cấu hình security
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // cors = crossOrigin truy cap ngoai nguon
        // csrf reques giả phá hethong
        // disable k cho phep cors csrf
        http.cors()
                // config file riêng
//                .configurationSource(request -> {
//                    CorsConfiguration cfg = new CorsConfiguration();
//                    cfg.setAllowedOrigins(Collections.singletonList("http://localhost:5173/")); // list.of // cấp phép cho reac
//                    cfg.setAllowedMethods(Collections.singletonList("*")); // cấp toàn bộ quyền post get put delte...
//                    cfg.setAllowCredentials(true);
//                    cfg.setAllowedHeaders(Collections.singletonList("*"));
//                    cfg.setAllowedHeaders(Collections.singletonList("Authorization"));
//                cfg.setMaxAge(); // thoi gian chờ reponse . mac dinh 1800s
//                    return cfg;
//                        })
                .and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/v6/auth/**").permitAll() // đầu ra api được phép truy cập hết
           //     .antMatchers("/api/v1/test/**").permitAll()
                .antMatchers( "/api/v1/test/admin").hasAnyAuthority("ADMIN")
                .antMatchers( "api/version1.0/daoTrangs/them").hasAnyAuthority("ADMIN")

          //      .antMatchers(HttpMethod.POST, "/api/suaThongTin").hasAuthority("TT")
                .anyRequest().authenticated() //  chặn truy cập các ánh xạ khác
                .and()
                .exceptionHandling().authenticationEntryPoint(jwtEntryPoin) // hứng lỗi khi authen sai
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);



        http.addFilterBefore( jwtTokenFilter(),  UsernamePasswordAuthenticationFilter.class);
    }

}
