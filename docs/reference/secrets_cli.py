"""
CLI tool for CAIP Secret Management

Provides command-line interface for initializing, managing, and rotating secrets
in both Azure Key Vault and encrypted file backends.

Usage:
    python -m caip_service_layer.secrets_cli init --mode offline --password
    python -m caip_service_layer.secrets_cli init --mode offline --keyfile /etc/caip/master.key
    python -m caip_service_layer.secrets_cli init --mode online --azure-kv-url https://vault.azure.net/
    python -m caip_service_layer.secrets_cli list
    python -m caip_service_layer.secrets_cli set flask_secret_key <value>
    python -m caip_service_layer.secrets_cli get flask_secret_key
    python -m caip_service_layer.secrets_cli delete flask_secret_key
    python -m caip_service_layer.secrets_cli rotate --new-password
"""

import os
import sys
import json
import base64
import argparse
import getpass
import secrets as py_secrets
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretsCLI:
    """CLI tool for secret management operations"""

    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self):
        """Create argument parser with subcommands"""
        parser = argparse.ArgumentParser(
            description='CAIP Secret Management CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  # Initialize offline mode with password
  %(prog)s init --mode offline --password

  # Initialize offline mode with key file
  %(prog)s init --mode offline --keyfile /etc/caip/master.key

  # Initialize Azure Key Vault mode
  %(prog)s init --mode online --azure-kv-url https://thalescrypto-kv01.vault.azure.net/

  # List all secrets (IDs only, not values)
  %(prog)s list

  # Set a secret
  %(prog)s set flask_secret_key <value>

  # Get a secret (careful - displays in terminal)
  %(prog)s get flask_secret_key

  # Delete a secret
  %(prog)s delete flask_secret_key

  # Rotate master key for offline mode
  %(prog)s rotate --current-password --new-password
            '''
        )

        subparsers = parser.add_subparsers(dest='command', help='Command to execute')

        # Init command
        init_parser = subparsers.add_parser('init', help='Initialize secrets storage')
        init_parser.add_argument('--mode', required=True, choices=['online', 'offline'],
                                help='Storage mode: online (Azure KV) or offline (encrypted file)')
        init_parser.add_argument('--azure-kv-url', help='Azure Key Vault URL (for online mode)')
        init_parser.add_argument('--azure-tenant-id', help='Azure tenant ID')
        init_parser.add_argument('--azure-client-id', help='Azure client ID')
        init_parser.add_argument('--azure-client-secret', help='Azure client secret')
        init_parser.add_argument('--password', action='store_true',
                                help='Use password-based encryption (offline mode)')
        init_parser.add_argument('--keyfile', help='Path to master key file (offline mode)')
        init_parser.add_argument('--output', default='/etc/caip/secrets.enc',
                                help='Output path for encrypted secrets file (default: /etc/caip/secrets.enc)')

        # List command
        list_parser = subparsers.add_parser('list', help='List all secret IDs')
        list_parser.add_argument('--config', help='Path to secrets file or config')

        # Set command
        set_parser = subparsers.add_parser('set', help='Set a secret value')
        set_parser.add_argument('secret_id', help='Secret identifier')
        set_parser.add_argument('value', nargs='?', help='Secret value (omit to read from stdin)')
        set_parser.add_argument('--config', help='Path to secrets file or config')
        set_parser.add_argument('--description', help='Secret description')

        # Get command
        get_parser = subparsers.add_parser('get', help='Get a secret value')
        get_parser.add_argument('secret_id', help='Secret identifier')
        get_parser.add_argument('--config', help='Path to secrets file or config')

        # Delete command
        delete_parser = subparsers.add_parser('delete', help='Delete a secret')
        delete_parser.add_argument('secret_id', help='Secret identifier')
        delete_parser.add_argument('--config', help='Path to secrets file or config')
        delete_parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')

        # Rotate command
        rotate_parser = subparsers.add_parser('rotate', help='Rotate master key (offline mode)')
        rotate_parser.add_argument('--current-password', action='store_true',
                                   help='Provide current password interactively')
        rotate_parser.add_argument('--current-keyfile', help='Path to current master key file')
        rotate_parser.add_argument('--new-password', action='store_true',
                                   help='Set new password interactively')
        rotate_parser.add_argument('--new-keyfile', help='Path for new master key file')
        rotate_parser.add_argument('--config', default='/etc/caip/secrets.enc',
                                   help='Path to secrets file')

        return parser

    def run(self, args=None):
        """Execute CLI command"""
        parsed_args = self.parser.parse_args(args)

        if not parsed_args.command:
            self.parser.print_help()
            return 1

        try:
            if parsed_args.command == 'init':
                return self.cmd_init(parsed_args)
            elif parsed_args.command == 'list':
                return self.cmd_list(parsed_args)
            elif parsed_args.command == 'set':
                return self.cmd_set(parsed_args)
            elif parsed_args.command == 'get':
                return self.cmd_get(parsed_args)
            elif parsed_args.command == 'delete':
                return self.cmd_delete(parsed_args)
            elif parsed_args.command == 'rotate':
                return self.cmd_rotate(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}")
                return 1

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def cmd_init(self, args):
        """Initialize secrets storage"""
        if args.mode == 'offline':
            return self._init_offline(args)
        elif args.mode == 'online':
            return self._init_online(args)

    def _init_offline(self, args):
        """Initialize encrypted file for offline mode"""
        output_path = args.output

        # Check if file already exists
        if os.path.exists(output_path):
            response = input(f"File {output_path} already exists. Overwrite? (yes/no): ")
            if response.lower() != 'yes':
                print("Aborted.")
                return 1

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Get or generate master key
        if args.keyfile:
            # Generate new random key file
            print(f"Generating random 256-bit master key...")
            master_key = py_secrets.token_bytes(32)

            with open(args.keyfile, 'wb') as f:
                f.write(master_key)

            # Set restrictive permissions
            os.chmod(args.keyfile, 0o400)

            print(f"Master key file created: {args.keyfile}")
            print(f"WARNING: Keep this file secure! Loss of this file means loss of all secrets.")

            kdf_method = "keyfile"
            salt = None
            iterations = None

        elif args.password:
            # Derive key from password
            password = getpass.getpass("Enter master password: ")
            password_confirm = getpass.getpass("Confirm master password: ")

            if password != password_confirm:
                print("Passwords do not match!", file=sys.stderr)
                return 1

            if len(password) < 12:
                print("Password must be at least 12 characters!", file=sys.stderr)
                return 1

            # Generate random salt
            salt = py_secrets.token_bytes(16)
            iterations = 600000  # OWASP recommendation

            print(f"Deriving encryption key (PBKDF2-HMAC-SHA256, {iterations} iterations)...")

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            master_key = kdf.derive(password.encode('utf-8'))

            kdf_method = "pbkdf2-hmac-sha256"

            print("Master key derived successfully.")

        else:
            print("Must specify either --password or --keyfile", file=sys.stderr)
            return 1

        # Create Fernet cipher
        fernet_key = base64.urlsafe_b64encode(master_key)
        fernet = Fernet(fernet_key)

        # Create initial secrets structure with Flask secret key
        initial_secrets = {
            "flask_secret_key": py_secrets.token_hex(32)  # Generate random Flask secret
        }

        print(f"Generated initial Flask secret key")

        # Encrypt secrets
        secrets_json = json.dumps(initial_secrets, indent=2)
        encrypted_blob = fernet.encrypt(secrets_json.encode('utf-8'))

        # Create metadata structure
        metadata = {
            "version": "1.0",
            "kdf": kdf_method,
            "encrypted_blob": encrypted_blob.decode('utf-8'),
            "created_at": datetime.utcnow().isoformat() + 'Z',
            "last_updated": datetime.utcnow().isoformat() + 'Z'
        }

        if salt:
            metadata["salt"] = base64.b64encode(salt).decode('utf-8')
            metadata["iterations"] = iterations

        # Write to file
        with open(output_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        # Set restrictive permissions
        os.chmod(output_path, 0o600)

        print(f"\nEncrypted secrets file created: {output_path}")
        print(f"Initial secrets: {list(initial_secrets.keys())}")
        print(f"\nTo use this configuration, set environment variables:")
        print(f"  export CAIP_SECRET_BACKEND=ENCRYPTED_FILE")
        print(f"  export CAIP_SECRETS_FILE={output_path}")

        if args.keyfile:
            print(f"  export CAIP_MASTER_KEYFILE={args.keyfile}")
        else:
            print(f"  export CAIP_MASTER_PASSWORD='<your-password>'")

        return 0

    def _init_online(self, args):
        """Initialize Azure Key Vault for online mode"""
        if not args.azure_kv_url:
            print("--azure-kv-url is required for online mode", file=sys.stderr)
            return 1

        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential, ClientSecretCredential

            # Determine authentication
            if args.azure_tenant_id and args.azure_client_id and args.azure_client_secret:
                credential = ClientSecretCredential(
                    tenant_id=args.azure_tenant_id,
                    client_id=args.azure_client_id,
                    client_secret=args.azure_client_secret
                )
                print("Using Service Principal authentication")
            else:
                credential = DefaultAzureCredential()
                print("Using Default Azure Credential authentication")

            # Create client
            client = SecretClient(vault_url=args.azure_kv_url, credential=credential)

            # Test connectivity
            print(f"Testing connectivity to {args.azure_kv_url}...")
            list(client.list_properties_of_secrets())[:1]  # Try to list one secret

            print("Connection successful!")

            # Create initial Flask secret
            flask_secret = py_secrets.token_hex(32)
            client.set_secret("caip-flask-secret", flask_secret, tags={
                "managed_by": "caip_secrets_cli",
                "created_at": datetime.utcnow().isoformat()
            })

            print("Created initial secret: caip-flask-secret")
            print(f"\nTo use this configuration, set environment variables:")
            print(f"  export CAIP_SECRET_BACKEND=AZURE_KEY_VAULT")
            print(f"  export AZURE_KEY_VAULT_URL={args.azure_kv_url}")

            if args.azure_tenant_id:
                print(f"  export AZURE_TENANT_ID={args.azure_tenant_id}")
                print(f"  export AZURE_CLIENT_ID={args.azure_client_id}")
                print(f"  export AZURE_CLIENT_SECRET='<secret>'")

            return 0

        except ImportError:
            print("Azure SDK not installed. Install with:", file=sys.stderr)
            print("  pip install azure-keyvault-secrets azure-identity", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to initialize Azure Key Vault: {e}", file=sys.stderr)
            return 1

    def cmd_list(self, args):
        """List all secret IDs"""
        from caip_service_layer.secret_service import init_secret_service

        config = self._load_config(args.config)
        service = init_secret_service(config)

        secret_ids = service.list_secrets()

        if not secret_ids:
            print("No secrets found.")
            return 0

        print(f"Found {len(secret_ids)} secret(s):")
        for sid in sorted(secret_ids):
            print(f"  - {sid}")

        return 0

    def cmd_set(self, args):
        """Set a secret value"""
        from caip_service_layer.secret_service import init_secret_service

        # Get value from argument or stdin
        if args.value:
            value = args.value
        else:
            print("Enter secret value (input hidden):")
            value = getpass.getpass("")

        config = self._load_config(args.config)
        service = init_secret_service(config)

        service.set_secret(args.secret_id, value, args.description)

        print(f"Secret '{args.secret_id}' stored successfully in {service.backend.value} backend")
        return 0

    def cmd_get(self, args):
        """Get a secret value"""
        from caip_service_layer.secret_service import init_secret_service

        config = self._load_config(args.config)
        service = init_secret_service(config)

        try:
            value = service.get_secret(args.secret_id)
            print(value)
            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def cmd_delete(self, args):
        """Delete a secret"""
        from caip_service_layer.secret_service import init_secret_service, SecretNotFoundError

        config = self._load_config(args.config)
        service = init_secret_service(config)

        # Confirm deletion
        if not args.confirm:
            response = input(f"Delete secret '{args.secret_id}'? (yes/no): ")
            if response.lower() != 'yes':
                print("Aborted.")
                return 1

        try:
            service.delete_secret(args.secret_id)
            print(f"Secret '{args.secret_id}' deleted successfully")
            return 0
        except SecretNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def cmd_rotate(self, args):
        """Rotate master key for encrypted file"""
        config_path = args.config

        if not os.path.exists(config_path):
            print(f"Secrets file not found: {config_path}", file=sys.stderr)
            return 1

        # Load current master key
        if args.current_keyfile:
            with open(args.current_keyfile, 'rb') as f:
                current_master_key = f.read()
        elif args.current_password:
            password = getpass.getpass("Enter current password: ")

            with open(config_path, 'r') as f:
                metadata = json.load(f)

            salt = base64.b64decode(metadata['salt'])
            iterations = metadata.get('iterations', 600000)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            current_master_key = kdf.derive(password.encode('utf-8'))
        else:
            print("Must specify --current-password or --current-keyfile", file=sys.stderr)
            return 1

        # Decrypt secrets with current key
        fernet = Fernet(base64.urlsafe_b64encode(current_master_key))

        with open(config_path, 'r') as f:
            data = json.load(f)

        try:
            decrypted = fernet.decrypt(data['encrypted_blob'].encode('utf-8'))
            secrets = json.loads(decrypted)
            print(f"Successfully decrypted {len(secrets)} secrets")
        except Exception as e:
            print(f"Failed to decrypt with current key: {e}", file=sys.stderr)
            return 1

        # Generate or derive new master key
        if args.new_keyfile:
            new_master_key = py_secrets.token_bytes(32)
            with open(args.new_keyfile, 'wb') as f:
                f.write(new_master_key)
            os.chmod(args.new_keyfile, 0o400)
            print(f"Generated new master key file: {args.new_keyfile}")

            kdf_method = "keyfile"
            salt = None
            iterations = None

        elif args.new_password:
            new_password = getpass.getpass("Enter new password: ")
            new_password_confirm = getpass.getpass("Confirm new password: ")

            if new_password != new_password_confirm:
                print("Passwords do not match!", file=sys.stderr)
                return 1

            salt = py_secrets.token_bytes(16)
            iterations = 600000

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            new_master_key = kdf.derive(new_password.encode('utf-8'))

            kdf_method = "pbkdf2-hmac-sha256"

        else:
            print("Must specify --new-password or --new-keyfile", file=sys.stderr)
            return 1

        # Encrypt with new key
        new_fernet = Fernet(base64.urlsafe_b64encode(new_master_key))
        encrypted_blob = new_fernet.encrypt(json.dumps(secrets, indent=2).encode('utf-8'))

        # Create backup
        backup_path = f"{config_path}.backup-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.rename(config_path, backup_path)
        print(f"Created backup: {backup_path}")

        # Write new encrypted file
        new_metadata = {
            "version": "1.0",
            "kdf": kdf_method,
            "encrypted_blob": encrypted_blob.decode('utf-8'),
            "created_at": data.get('created_at', datetime.utcnow().isoformat() + 'Z'),
            "last_updated": datetime.utcnow().isoformat() + 'Z',
            "rotated_from": data.get('last_updated')
        }

        if salt:
            new_metadata["salt"] = base64.b64encode(salt).decode('utf-8')
            new_metadata["iterations"] = iterations

        with open(config_path, 'w') as f:
            json.dump(new_metadata, f, indent=2)

        os.chmod(config_path, 0o600)

        print(f"Master key rotated successfully!")
        print(f"Secrets file updated: {config_path}")

        return 0

    def _load_config(self, config_path):
        """Load configuration for secret service"""
        if config_path:
            # Use specified config file
            return {
                'secret_backend': 'ENCRYPTED_FILE',
                'secrets_file_path': config_path,
                'master_password': os.getenv('CAIP_MASTER_PASSWORD'),
                'master_keyfile': os.getenv('CAIP_MASTER_KEYFILE')
            }
        else:
            # Use environment variables
            return {
                'secret_backend': os.getenv('CAIP_SECRET_BACKEND', 'ENCRYPTED_FILE'),
                'azure_kv_url': os.getenv('AZURE_KEY_VAULT_URL'),
                'azure_tenant_id': os.getenv('AZURE_TENANT_ID'),
                'azure_client_id': os.getenv('AZURE_CLIENT_ID'),
                'azure_client_secret': os.getenv('AZURE_CLIENT_SECRET'),
                'secrets_file_path': os.getenv('CAIP_SECRETS_FILE', '/etc/caip/secrets.enc'),
                'master_password': os.getenv('CAIP_MASTER_PASSWORD'),
                'master_keyfile': os.getenv('CAIP_MASTER_KEYFILE')
            }


def main():
    """Main entry point"""
    cli = SecretsCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
