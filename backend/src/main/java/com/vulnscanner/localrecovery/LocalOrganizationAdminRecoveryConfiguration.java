package com.vulnscanner.localrecovery;

import com.vulnscanner.application.config.PasswordEncoderConfiguration;
import com.vulnscanner.application.user.UserRepository;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration(proxyBeanMethods = false)
@EnableAutoConfiguration(exclude = FlywayAutoConfiguration.class)
@EntityScan("com.vulnscanner.application")
@EnableJpaRepositories(basePackageClasses = UserRepository.class)
@Import({
        PasswordEncoderConfiguration.class,
        LocalOrganizationAdminRecoveryService.class,
        LocalOrganizationAdminRecoveryRunner.class
})
public class LocalOrganizationAdminRecoveryConfiguration {
}
