package org.keycloak.credential.hash;

import org.junit.Test;
import org.keycloak.credential.CredentialModel;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.keycloak.models.PasswordPolicy.empty;


public class Pbkdf2PasswordHashProviderTest {

    @Test
    public void should_encode_and_verify_password() {
        String providerId = "pbkdf2-sha256";
        int iterations = 27500;
        String rawPassword = "mySuperPassword";
        Pbkdf2PasswordHashProvider hashProvider = new Pbkdf2PasswordHashProvider(providerId, "PBKDF2WithHmacSHA256", iterations);

        CredentialModel cred = new CredentialModel();
        hashProvider.encode(rawPassword, -1, cred);

        assertThat(cred.getAlgorithm(), equalTo(providerId));
        assertThat(cred.getValue(), notNullValue());
        assertThat(cred.getSalt(), notNullValue());
        assertThat(cred.getHashIterations(), equalTo(iterations));

        boolean verified = hashProvider.verify(rawPassword, cred);
        assertThat(verified, equalTo(true));
    }

    @Test
    public void should_verify_hash_with_different_length() {
        String providerId = "pbkdf2-sha256";
        String rawPassword = "mySuperPassword";
        Pbkdf2PasswordHashProvider defaultHashProvider = new Pbkdf2PasswordHashProvider(providerId, "PBKDF2WithHmacSHA256", 27_500);
        Pbkdf2PasswordHashProvider specificKeySizeHashProvider = new Pbkdf2PasswordHashProvider(providerId, "PBKDF2WithHmacSHA256", 27_500, 256);

        CredentialModel cred = new CredentialModel();
        specificKeySizeHashProvider.encode(rawPassword, -1, cred);

        assertTrue(defaultHashProvider.verify(rawPassword, cred));
        assertFalse(defaultHashProvider.policyCheck(empty(), cred));
    }
}