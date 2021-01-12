package ar.coders.tokenauth.bussiness.config;

import ar.coders.tokenauth.bussiness.security.InitialAuthenticationFilter;
import ar.coders.tokenauth.bussiness.security.JwtAuthenticationFilter;
import ar.coders.tokenauth.bussiness.security.OtpAuthenticationProvider;
import ar.coders.tokenauth.bussiness.security.UsernamePasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private InitialAuthenticationFilter initialAuthenticationFilter;
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private OtpAuthenticationProvider otpAuthenticationProvider;
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;


    public SecurityConfig(InitialAuthenticationFilter initialAuthenticationFilter,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          OtpAuthenticationProvider otpAuthenticationProvider,
                          UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider
    ) {
        this.initialAuthenticationFilter = initialAuthenticationFilter;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.otpAuthenticationProvider = otpAuthenticationProvider;
        this.usernamePasswordAuthenticationProvider = usernamePasswordAuthenticationProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(otpAuthenticationProvider)
            .authenticationProvider(usernamePasswordAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.addFilterAt(initialAuthenticationFilter, BasicAuthenticationFilter.class)
            .addFilterAt(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
        http.authorizeRequests().anyRequest().authenticated();
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
