[![Actions Status](https://github.com/rkuijt/spring-security-method-whitelisting/workflows/Build/badge.svg)](https://github.com/rkuijt/spring-security-method-whitelisting/actions)
[![Actions Status](https://github.com/rkuijt/spring-security-method-whitelisting/workflows/Publish/badge.svg)](https://github.com/rkuijt/spring-security-method-whitelisting/actions)
# Spring Boot Controller Method Whitelisting
_Resources should be protected by default_

Use annotation based access controls in Spring Boot controllers in a secure way.

## What does this library do?
Consider the following use case

We have a REST controller which has the following methods
```java
@RestController
@RequestMapping(value = "/api")
@ComponentScan
public class SomethingController {

    @RequestMapping(value = "/public", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
    
    @RequestMapping(value = "/only-authenticated-users", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
    
    @RequestMapping(value = "/only-authorized-users", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
}
```
We can map the resources to our security configuration as in the following example:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .csrf().disable()
            .exceptionHandling()
            .and()
            .httpBasic()
            .and()
            .authorizeRequests()
            .antMatchers("/api/public").permitAll()
            .antMatchers("/api/only-authenticated-users").authenticated()
            .antMatchers("/api/public").hasRole("SOME_ROLE")
            .anyRequest().authenticated();
}
```
This can become a little bit messy, so we decide to move on to annotation based security a.k.a. Method Security.  
It allows us to annotate controller methods and remove the antMatcher directives from our security configuration.
Our security configuration becomes as follows:
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .csrf().disable()
            .exceptionHandling()
            .and()
            .httpBasic()
            .and()
            .authorizeRequests()
            .anyRequest().permitAll();
}
```

**Caveat 1: The authorization scheme specified in the HttpSecurity configuration should be more permissive then the access level in our annotations as it is evaluated before the
 annotations are. Since we have a public endpoint, we will have to pick `permitAll()`**

Our controller would then look like this:
```java
@RestController
@RequestMapping(value = "/api")
@ComponentScan
public class SomethingController {

    @PreAuthorize("permitAll()")
    @RequestMapping(value = "/public", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
    
    @PreAuthorize("isAuthenticated()")
    @RequestMapping(value = "/only-authenticated-users", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
    
    @Secured("SOME_ROLE")
    @RequestMapping(value = "/only-authorized-users", method = RequestMethod.GET)
    public Optional<Something> getSomething() {
        return somethingService.getSomething(name);
    }
}
```
That's nice isn't it? But then a developer adds a new endpoint intended for authorized users only and forgets to add the proper security annotation.
The resource that should be protected is now open to everyone.

This is the problem this library solves. By applying the `SecureMethodSecurityMetadataSource` to your security configuration all endpoints which are not explicitly annotated will be
 denied access to by default. This makes using annotation based authentication and authorization a lot more secure.
 
## How do I use this library
Add the following class to your code:
```java
import com.rkuijt.spring.methodsecurity.whitelisting.metadatasource.SecureMethodSecurityMetadataSource;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {
    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return new SecureMethodSecurityMetadataSource();
    }

}
```
Then make sure to use a permissive HttpSecurity configuration:
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .csrf().disable()
            .exceptionHandling()
            .and()
            .httpBasic()
            .and()
            .authorizeRequests().anyRequest().permitAll();
}
```
Note that your HttpSecurity configuration now allows all requests by default. The requests are then either handled by annotations or they are denied by `SecureMethodSecurityMetadataSource`.

You can off course restrict the authorization scheme to your specific situation but make sure that this configuration is not more restrictive than your annotations or you won't be able to
 access resources.

## Annotations

### Spring Annotations
You can use annotations provided by Spring Boot to control access to resources:

`@PreAuthorize("expression")` : Custom pre-authentication flow, see [expression Documentation](https://docs.spring.io/spring-security/site/docs/3.0.x/reference/el-access.html)  
`@PostAuthorize("expression")` : Custom post-authentication flow, see [expression Documentation](https://docs.spring.io/spring-security/site/docs/3.0.x/reference/el-access.html)  
`@Secured("SOME_ROLE")` : Define which roles have access to a resource

### Additional Annotations
The library includes some additional annotations to make life easier:

`@Authenticated` : Allows authenticated users to access the annotated (Any role)  
`@Public` : Allows everyone to access a specified resource


