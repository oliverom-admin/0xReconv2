"""
VaultService unit tests.
No database or running container required — all tests use temp files.
"""
from __future__ import annotations

import pytest

from recon_api.services.vault import (
    VaultDecryptionError,
    VaultNotInitializedError,
    VaultService,
)


@pytest.fixture
async def vault(tmp_path):
    """A fresh initialised vault in a temp directory."""
    v = VaultService(
        str(tmp_path / "test.enc"),
        "test_master_password_32_chars_ok!"
    )
    await v.initialize()
    return v


# — Init tests ————————————————————————————————————————————————————————————

class TestVaultInit:

    async def test_creates_vault_file_on_first_init(self, tmp_path):
        path = tmp_path / "new.enc"
        v = VaultService(str(path), "password_at_least_32_chars_long!")
        await v.initialize()
        assert path.exists()

    async def test_loads_existing_vault(self, tmp_path):
        path = str(tmp_path / "existing.enc")
        pw = "password_at_least_32_chars_long!"
        v1 = VaultService(path, pw)
        await v1.initialize()
        await v1.set_secret("key", "value")

        v2 = VaultService(path, pw)
        await v2.initialize()
        assert await v2.get_secret("key") == "value"

    async def test_wrong_password_raises_decryption_error(self, tmp_path):
        path = str(tmp_path / "wp.enc")
        v1 = VaultService(path, "correct_password_32_chars_exactly")
        await v1.initialize()

        v2 = VaultService(path, "wrong__password_32_chars_exactly!")
        with pytest.raises(VaultDecryptionError):
            await v2.initialize()

    async def test_uninitialized_raises_on_access(self, tmp_path):
        v = VaultService(str(tmp_path / "uninit.enc"),
                         "password_32_chars_exactly_here!!")
        with pytest.raises(VaultNotInitializedError):
            await v.get_secret("anything")


# — Crypto constant tests —————————————————————————————————————————————————

class TestVaultCryptoConstants:
    """
    These tests lock in the crypto parameters.
    Failures here mean something changed that would break existing vault files.
    """

    def test_iterations_is_600000(self):
        assert VaultService.ITERATIONS == 600_000

    def test_nonce_length_is_12(self):
        assert VaultService.NONCE_LENGTH == 12

    def test_salt_length_is_16(self):
        assert VaultService.SALT_LENGTH == 16

    def test_key_length_is_32(self):
        assert VaultService.KEY_LENGTH == 32


# — Secret tests ——————————————————————————————————————————————————————————

class TestVaultSecrets:

    async def test_set_and_get(self, vault):
        await vault.set_secret("db_password", "s3cr3t!")
        assert await vault.get_secret("db_password") == "s3cr3t!"

    async def test_missing_key_returns_none(self, vault):
        assert await vault.get_secret("nonexistent") is None

    async def test_overwrite_secret(self, vault):
        await vault.set_secret("k", "v1")
        await vault.set_secret("k", "v2")
        assert await vault.get_secret("k") == "v2"

    async def test_multiple_secrets_independent(self, vault):
        await vault.set_secret("a", "alpha")
        await vault.set_secret("b", "beta")
        assert await vault.get_secret("a") == "alpha"
        assert await vault.get_secret("b") == "beta"


# — PKI key tests —————————————————————————————————————————————————————————

class TestVaultPKIKeys:

    async def test_set_and_get_key(self, vault):
        pem = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
        await vault.set_key("internal-ca-key", pem)
        assert await vault.get_key("internal-ca-key") == pem

    async def test_missing_key_returns_none(self, vault):
        assert await vault.get_key("no-such-key") is None

    async def test_delete_key(self, vault):
        await vault.set_key("temp", "pem-data")
        await vault.delete_key("temp")
        assert await vault.get_key("temp") is None

    async def test_canonical_vault_key_names(self, vault):
        """
        All canonical vault key names must round-trip correctly.
        These names are embedded in reports and vault files — must not change.
        """
        names = [
            "internal-ca-key",
            "engagement-ca-key-abcdef12",
            "report-signing-key-abcdef12",
            "report-viewer-key-user123-report-abc12345",
        ]
        for name in names:
            await vault.set_key(name, f"pem-data-for-{name}")
        for name in names:
            result = await vault.get_key(name)
            assert result == f"pem-data-for-{name}", \
                f"Key name '{name}' did not round-trip"


# — Persistence tests —————————————————————————————————————————————————————

class TestVaultPersistence:

    async def test_secret_survives_reload(self, tmp_path):
        path = str(tmp_path / "persist.enc")
        pw = "password_at_least_32_chars_long!"
        v1 = VaultService(path, pw)
        await v1.initialize()
        await v1.set_secret("persist_key", "persisted_value")

        v2 = VaultService(path, pw)
        await v2.initialize()
        assert await v2.get_secret("persist_key") == "persisted_value"

    async def test_key_survives_reload(self, tmp_path):
        path = str(tmp_path / "persist_key.enc")
        pw = "password_at_least_32_chars_long!"
        pem = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
        v1 = VaultService(path, pw)
        await v1.initialize()
        await v1.set_key("internal-ca-key", pem)

        v2 = VaultService(path, pw)
        await v2.initialize()
        assert await v2.get_key("internal-ca-key") == pem

    async def test_atomic_write_no_data_loss(self, tmp_path):
        path = str(tmp_path / "atomic.enc")
        v = VaultService(path, "password_at_least_32_chars_long!")
        await v.initialize()
        for i in range(10):
            await v.set_secret(f"key{i}", f"val{i}")
        for i in range(10):
            assert await v.get_secret(f"key{i}") == f"val{i}", \
                f"Lost key{i} after sequential writes"


# — Health tests ——————————————————————————————————————————————————————————

class TestVaultHealth:

    async def test_health_uninitialized(self, tmp_path):
        v = VaultService(str(tmp_path / "h.enc"),
                         "password_32_chars_exactly_here!!")
        h = await v.health()
        assert h["status"] == "uninitialized"

    async def test_health_after_init(self, vault):
        h = await vault.health()
        assert h["status"] == "ok"
        assert "secrets_count" in h
        assert "keys_count" in h

    async def test_health_counts_accurately(self, vault):
        await vault.set_secret("s1", "v1")
        await vault.set_secret("s2", "v2")
        await vault.set_key("k1", "pem1")
        h = await vault.health()
        assert h["secrets_count"] == 2
        assert h["keys_count"] == 1
