/*
 * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve
 * Copyright (C) 2013-2024 SteVe Community Team
 * All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package de.rwth.idsg.steve.service;

import com.azure.core.exception.AzureException;
import com.azure.security.keyvault.secrets.SecretClient;
import com.google.common.base.Strings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SecretResolver {

    private final SecretClient secretClient;

    @Autowired
    public SecretResolver(SecretClient secretClient) {
        this.secretClient = secretClient;
    }

    public String resolveOrFallback(String vaultKey, String fallbackValue) {
        if (!Strings.isNullOrEmpty(vaultKey)) {
            return readVault(vaultKey);
        }

        if (!Strings.isNullOrEmpty(fallbackValue)) {
            return fallbackValue;
        }

        throw new RuntimeException("Neither a vault location nor a fallback value have been configured for one or more secrets.");
    }

    private String readVault(String key) {
        String value;
        try {
            value = secretClient.getSecret(key).getValue();
        } catch (final AzureException exception) {
            throw createVaultReadException(key, exception);
        }

        if (Strings.isNullOrEmpty(value)) {
            throw createVaultReadException(key, null);
        }

        final var message = "[Azure] Got secret value for '%s' of length (%d)".formatted(key, value.length());
        log.warn(message);

        return value;
    }

    private RuntimeException createVaultReadException(String key, Exception source) {
        return new RuntimeException("Could not get a valid secret value for '%s' from vault.".formatted(key), source);
    }

}
