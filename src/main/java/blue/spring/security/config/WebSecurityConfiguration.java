package blue.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Configurable
@EnableWebSecurity
@Order(6)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private OAuth2ClientContext clientContext;

    @Autowired
    public void setClientContext(OAuth2ClientContext clientContext) {
        this.clientContext = clientContext;
    }

    @Bean
    @ConfigurationProperties("google")
    public ClientResources google() { return new ClientResources(); }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() { return new ClientResources(); }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/**.html", "/**.js")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .permitAll()
                .and()
                .addFilterAt(ssoFilter(), BasicAuthenticationFilter.class)
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(filter(google(), "/login/google"));
        filters.add(filter(github(), "/login/github"));
        filter.setFilters(filters);
        return filter;
    }

    private OAuth2ClientAuthenticationProcessingFilter filter(ClientResources client, String path) {

        OAuth2ClientAuthenticationProcessingFilter oAuth2Filter = new OAuth2ClientAuthenticationProcessingFilter(
                path);

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(), clientContext);
        oAuth2Filter.setRestTemplate(oAuth2RestTemplate);

        oAuth2Filter.setTokenServices(new UserInfoTokenServices(client.getResource().getUserInfoUri(),
                client.getClient().getClientId()));

        oAuth2Filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                this.setDefaultTargetUrl("/");
                super.onAuthenticationSuccess(request, response, authentication);
            }
        });

        return oAuth2Filter;
    }
}
