/*
 * MIT License
 *
 * Copyright (c) 2020 Robin Kuijt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.rkuijt.spring.methodsecurity.whitelisting.metadatasource;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.*;

import static org.springframework.security.access.annotation.Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE;

/**
 *  Allows for secure access control annotation usage in controllers. By default denies all access to controllers & methods which do not have authorization annotations.
 *  <span color="red">Make sure your HttpSecurity authorization scheme is permissive, check the readme for details.</span>
 *  Add the following configuration to your application to use this MetadataSource:
 * <pre>
 * &commat;Configuration
 * &commat;EnableWebSecurity
 * &commat;EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
 * public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {
 * &commat;Override
 * protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
 * return new SecureMethodSecurityMetadataSource();
 * }
 *
 * </pre>
 */
public class SecureMethodSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource {

    /**
     * Holds the annotation classes which should be checked for. If these are found on the type then we do not deny access.
     */
    private final Set<Class<? extends Annotation>>  securityAnnotations = new HashSet<>(Arrays.asList(
            PreAuthorize.class,
            PostAuthorize.class,
            Secured.class
    ));

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    protected Collection<ConfigAttribute> findAttributes(Class<?> clazz) {
        return null;
    }

    /**
     * Makes sure that access is denied to controllers and methods which are not explicitly annotated.
     * @param method the method which is called by the request.
     * @param targetClass the class which is called by the request.
     * @return A list of ConfigAttribute's. Used for determining whether access should be denied or not.
     */
    @Override
    protected Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
        List<ConfigAttribute> attributes = new ArrayList<>();

        // Only process controllers
        if (AnnotationUtils.findAnnotation(targetClass, Controller.class) != null) {
            // Check if controller is already annotated, if so, don't deny access.
            if (hasAccessControlsApplied(targetClass)) {
                return null;
            }

            // Check if controller's method is already annotated, if so, don't deny access.
            if (hasAccessControlsApplied(method)) {
                return null;
            }

            // If both the controller and it's targeted method lack access controls, deny access.
            attributes.add(DENY_ALL_ATTRIBUTE);
        }

        // If class is not a Controller, ignore.
        return attributes;
    }

    private boolean hasAccessControlsApplied(Class<?> clazz) {
        return securityAnnotations.stream().anyMatch(annotationClass -> AnnotationUtils.findAnnotation(clazz, annotationClass) != null);
    }

    private boolean hasAccessControlsApplied(Method method) {
        return securityAnnotations.stream().anyMatch(annotationClass -> AnnotationUtils.findAnnotation(method, annotationClass) != null);
    }

}
