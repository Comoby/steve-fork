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
package de.rwth.idsg.steve.config;

import com.azure.core.exception.AzureException;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import de.rwth.idsg.steve.service.SecretResolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecretResolverTest {

    private static SecretClient secretClient;
    private static SecretResolver impl;

    @BeforeAll
    static void setUp() {
        secretClient = mock(SecretClient.class);
        impl = new SecretResolver(secretClient);
    }

    @Test
    void resolve() {
        when(secretClient.getSecret("test")).thenReturn(new KeyVaultSecret("test", "secret"));
        assertEquals("secret", impl.resolveOrFallback("test", "secret-fallback"));
        verify(secretClient).getSecret("test");

        fail("ups");
    }

    @Test
    void fallback() {
        assertEquals("secret-fallback", impl.resolveOrFallback(null, "secret-fallback"));
        assertEquals("secret-fallback", impl.resolveOrFallback("", "secret-fallback"));
        verify(secretClient, never()).getSecret("test");
    }

    @Test
    void missingFallback() {
        assertThrows(RuntimeException.class, () -> impl.resolveOrFallback(null, null));
        assertThrows(RuntimeException.class, () -> impl.resolveOrFallback("", ""));
    }

    @Test
    void failedFallback() {
        when(secretClient.getSecret("test")).thenThrow(AzureException.class);

        assertThrows(RuntimeException.class, () -> impl.resolveOrFallback(null, null));
        assertThrows(RuntimeException.class, () -> impl.resolveOrFallback("", ""));
    }

    @Test
    void missingResolvedValue() {
        when(secretClient.getSecret("test")).thenReturn(new KeyVaultSecret("test", ""));
        assertThrows(RuntimeException.class, () -> impl.resolveOrFallback(null, null));
        verify(secretClient, never()).getSecret("test");
    }
}