/*
    Copyright 2018 Marcus Trautwig

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */
package de.trautwig.spring.boot.ansible.vault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigFileApplicationListener;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static java.util.Arrays.asList;

/**
 * {@link EnvironmentPostProcessor} that loads "Ansible Vault" encrypted configuration files from well-known locations.
 * By default, a 'vault.yml' will be loaded in the following locations:
 * <ul>
 * <li>classpath:</li>
 * <li>classpath:config/</li>
 * <li>file:./</li>
 * <li>file:./config/</li>
 * </ul>
 * <p>
 * Additional files will also be loaded depending on the active profiles. For example, if a 'production' profile is
 * active, 'vault-production.yml' will also be considered (if it exists).
 * <p>
 * In order to decrypt the Vault, a password is needed. This is fetched from any registered {@link AnsibleVaultPasswordSource}.
 * By default, a text file 'vault.secrets' in the current working directory is used. Otherwise, a password can be specified
 * by via the Environment property 'ansible.vault.secret'. If the value starts with '@', the remainder is the path to
 * a password file, otherwise the value is assumed to be the password. All Vault files must use the same password.
 *
 * @see ConfigFileApplicationListener
 * @see AnsibleVaultPasswordSource
 */
public class AnsibleVaultEnvironment implements EnvironmentPostProcessor {
    private static final List<String> DEFAULT_SEARCH_LOCATIONS = asList(
            "file:./config/",
            "file:./",
            "classpath:/config/",
            "classpath:/");
    private static final String DEFAULT_NAME = "vault";
    private static final String FILE_EXTENSION = ".yml";

    public static final String VAULT_NAME_PROPERTY = "ansible.vault.name";
    public static final String VAULT_SECRET_PROPERTY = "ansible.vault.secret";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        try (PasswordSupplier passwordSupplier = new PasswordSupplier(environment)) {
            new Loader(environment, passwordSupplier).load();
        }
    }

    private static class PasswordSupplier implements Supplier<char[]>, AutoCloseable {
        private final Environment environment;
        private char[] password;

        public PasswordSupplier(Environment environment) {
            this.environment = environment;
        }

        @Override
        public char[] get() {
            if (this.password == null) {
                this.password = getFromSources();
            }
            return this.password;
        }

        private char[] getFromSources() {
            Optional<char[]> password = SpringFactoriesLoader.loadFactories(AnsibleVaultPasswordSource.class, getClass().getClassLoader()).stream().
                    map(source -> source.getVaultPassword(environment)).filter(pwd -> pwd != null).findFirst();

            if (!password.isPresent()) {
                throw new RuntimeException("unable to determine vault password, check environment property '" + VAULT_SECRET_PROPERTY + "'");
            }

            return password.get();
        }

        @Override
        public void close() {
            if (this.password != null) {
                Arrays.fill(this.password, '\0');
            }
        }
    }

    private static class Loader {
        private final ConfigurableEnvironment environment;
        private final Supplier<char[]> vaultPasswordSupplier;
        private final ResourceLoader resourceLoader = new DefaultResourceLoader();
        private final YamlPropertySourceLoader yamlLoader = new YamlPropertySourceLoader();

        Loader(ConfigurableEnvironment environment, Supplier<char[]> vaultPasswordSupplier) {
            this.environment = environment;
            this.vaultPasswordSupplier = vaultPasswordSupplier;
        }

        public void load() {
            // Load any profile-specific Vault files
            for (String profile : environment.getActiveProfiles()) {
                load(profile).forEach(environment.getPropertySources()::addLast);
            }

            // Load the default Vault file last
            load(null).forEach(environment.getPropertySources()::addLast);
        }

        private Stream<PropertySource<?>> load(String profile) {
            return getSearchLocations().stream()
                    .flatMap(location -> {
                boolean isFolder = location.endsWith("/");
                if (isFolder) {
                    return getSearchNames()
                            .flatMap(name -> load(location + name, profile));
                } else {
                    return load(location, profile);
                }
            });
        }

        private Stream<PropertySource<?>> load(String prefix, String profile) {
            String profileSpecificFile;
            if (profile != null) {
                profileSpecificFile = prefix + "-" + profile + FILE_EXTENSION;
            } else {
                profileSpecificFile = prefix + FILE_EXTENSION;
            }

            Resource resource = this.resourceLoader.getResource(profileSpecificFile);
            if (resource != null && resource.exists())
                return loadVault(resource).stream();
            else
                return Stream.empty();
        }

        private List<PropertySource<?>> loadVault(Resource resource) {
            final String propertySourceName = "vault: [" + resource.toString() + "]";
            try {
                return yamlLoader.load(propertySourceName, new AnsibleVaultResource(resource, vaultPasswordSupplier.get()));
            } catch (Exception e) {
                throw new RuntimeException("unable to load " + propertySourceName, e);
            }
        }

        private Stream<String> getSearchNames() {
            String vaultName = this.environment.getProperty(VAULT_NAME_PROPERTY);
            if (vaultName == null)
                return Stream.of(DEFAULT_NAME);
            else
                return asResolvedSet(vaultName).stream();
        }

        private Set<String> getSearchLocations() {
            String configLocation = this.environment.getProperty(ConfigFileApplicationListener.CONFIG_LOCATION_PROPERTY);
            if (configLocation != null)
                return getSearchLocations(configLocation);
            else {
                String additionalConfigLocation = this.environment.getProperty(ConfigFileApplicationListener.CONFIG_ADDITIONAL_LOCATION_PROPERTY);
                if (additionalConfigLocation == null)
                    return new LinkedHashSet<>(DEFAULT_SEARCH_LOCATIONS);
                else {
                    Set<String> locations = getSearchLocations(additionalConfigLocation);
                    locations.addAll(DEFAULT_SEARCH_LOCATIONS);
                    return locations;
                }
            }
        }

        private Set<String> getSearchLocations(String configLocation) {
            Set<String> locations = new LinkedHashSet<>();
            for (String path : asResolvedSet(configLocation)) {
                if (!path.contains("$")) {
                    path = StringUtils.cleanPath(path);
                    if (!ResourceUtils.isUrl(path)) {
                        path = ResourceUtils.FILE_URL_PREFIX + path;
                    }
                }
                locations.add(path);
            }
            return locations;
        }

        private Set<String> asResolvedSet(String value) {
            List<String> list = asList(StringUtils.trimArrayElements(
                    StringUtils.commaDelimitedListToStringArray(
                            this.environment.resolvePlaceholders(value))));
            Collections.reverse(list);
            return new LinkedHashSet<>(list);
        }
    }
}
