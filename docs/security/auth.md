# Authentication & Authorization

<img src="../images/hero-security.svg" alt="Authentication and Authorization" class="hero-image" role="img" aria-label="Authentication and Authorization Hero Image">

## Overview

Proper authentication and authorization are critical for securing AI agents. These mechanisms ensure that only legitimate users can access your agent and that they can only perform actions they're permitted to.

## Authentication Methods

### 1. Azure Active Directory (Azure AD)

The recommended authentication method for enterprise applications:

```python
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from msal import ConfidentialClientApplication
import os

class AzureADAuth:
    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        
        self.app = ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=self.client_secret
        )
    
    async def verify_token(self, token: str) -> dict:
        """
        Verify and decode JWT token from Azure AD.
        
        Returns:
            User information from token
        """
        try:
            # Verify token with Azure AD
            result = self.app.acquire_token_on_behalf_of(
                user_assertion=token,
                scopes=["User.Read"]
            )
            
            return {
                "user_id": result["sub"],
                "email": result.get("email"),
                "name": result.get("name"),
                "roles": result.get("roles", [])
            }
        except Exception as e:
            raise AuthenticationError(f"Token verification failed: {str(e)}")
```

### 2. API Key Authentication

For service-to-service communication:

```python
import secrets
import hashlib
from datetime import datetime, timedelta

class APIKeyManager:
    def __init__(self):
        self.keys = {}  # In production, use a database
    
    def generate_key(self, user_id: str, expiry_days: int = 90) -> str:
        """
        Generate a secure API key for a user.
        """
        # Generate random key
        raw_key = secrets.token_urlsafe(32)
        
        # Hash for storage
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Store metadata
        self.keys[key_hash] = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=expiry_days),
            "active": True
        }
        
        return raw_key
    
    def verify_key(self, api_key: str) -> dict:
        """
        Verify API key and return user information.
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash not in self.keys:
            raise AuthenticationError("Invalid API key")
        
        key_data = self.keys[key_hash]
        
        # Check if active
        if not key_data["active"]:
            raise AuthenticationError("API key is inactive")
        
        # Check expiration
        if datetime.utcnow() > key_data["expires_at"]:
            raise AuthenticationError("API key has expired")
        
        return {"user_id": key_data["user_id"]}
    
    def revoke_key(self, api_key: str):
        """Revoke an API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        if key_hash in self.keys:
            self.keys[key_hash]["active"] = False
```

### 3. Managed Identity

For Azure service-to-service authentication:

```python
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

class ManagedIdentityAuth:
    def __init__(self):
        # Automatically uses the managed identity assigned to the resource
        self.credential = ManagedIdentityCredential()
    
    def get_secret(self, vault_url: str, secret_name: str) -> str:
        """
        Retrieve secret from Key Vault using managed identity.
        """
        client = SecretClient(vault_url=vault_url, credential=self.credential)
        secret = client.get_secret(secret_name)
        return secret.value
    
    async def authenticate_to_service(self, scope: str) -> str:
        """
        Get access token for Azure service.
        """
        token = await self.credential.get_token(scope)
        return token.token
```

## Authorization Strategies

### Role-Based Access Control (RBAC)

Define roles and permissions:

```python
from enum import Enum
from typing import Set

class Permission(Enum):
    READ_AGENT = "agent:read"
    USE_AGENT = "agent:use"
    CONFIGURE_AGENT = "agent:configure"
    VIEW_LOGS = "logs:view"
    ADMIN = "admin:all"

class Role(Enum):
    USER = "user"
    POWER_USER = "power_user"
    ADMIN = "admin"

# Define role permissions
ROLE_PERMISSIONS = {
    Role.USER: {
        Permission.READ_AGENT,
        Permission.USE_AGENT
    },
    Role.POWER_USER: {
        Permission.READ_AGENT,
        Permission.USE_AGENT,
        Permission.VIEW_LOGS
    },
    Role.ADMIN: {
        Permission.READ_AGENT,
        Permission.USE_AGENT,
        Permission.CONFIGURE_AGENT,
        Permission.VIEW_LOGS,
        Permission.ADMIN
    }
}

class AuthorizationService:
    def __init__(self):
        self.user_roles = {}  # In production, use a database
    
    def assign_role(self, user_id: str, role: Role):
        """Assign a role to a user."""
        self.user_roles[user_id] = role
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get all permissions for a user."""
        role = self.user_roles.get(user_id, Role.USER)
        return ROLE_PERMISSIONS.get(role, set())
    
    def check_permission(self, user_id: str, required_permission: Permission) -> bool:
        """Check if user has a specific permission."""
        user_permissions = self.get_user_permissions(user_id)
        return required_permission in user_permissions or Permission.ADMIN in user_permissions
    
    def require_permission(self, required_permission: Permission):
        """Decorator to require a specific permission."""
        def decorator(func):
            async def wrapper(*args, user_id: str, **kwargs):
                if not self.check_permission(user_id, required_permission):
                    raise PermissionError(f"Missing required permission: {required_permission.value}")
                return await func(*args, user_id=user_id, **kwargs)
            return wrapper
        return decorator
```

### Attribute-Based Access Control (ABAC)

More fine-grained control based on attributes:

```python
from typing import Dict, Any

class ABACPolicy:
    def __init__(self):
        self.policies = []
    
    def add_policy(self, policy_func):
        """Add a policy function."""
        self.policies.append(policy_func)
    
    def evaluate(self, user: Dict[str, Any], resource: Dict[str, Any], action: str) -> bool:
        """
        Evaluate all policies to determine if action is allowed.
        
        Args:
            user: User attributes (role, department, etc.)
            resource: Resource attributes (owner, sensitivity, etc.)
            action: Action being attempted (read, write, delete)
        
        Returns:
            True if action is allowed, False otherwise
        """
        # All policies must pass
        return all(policy(user, resource, action) for policy in self.policies)

# Example policies
def owner_policy(user, resource, action):
    """Allow resource owner full access."""
    return user["id"] == resource.get("owner_id")

def department_policy(user, resource, action):
    """Allow users in the same department to read."""
    if action == "read":
        return user["department"] == resource.get("department")
    return False

def admin_policy(user, resource, action):
    """Allow admins all access."""
    return user.get("role") == "admin"

# Create ABAC service
abac = ABACPolicy()
abac.add_policy(owner_policy)
abac.add_policy(department_policy)
abac.add_policy(admin_policy)

# Usage
user = {"id": "user123", "department": "sales", "role": "user"}
resource = {"id": "doc456", "owner_id": "user789", "department": "sales"}
can_read = abac.evaluate(user, resource, "read")
```

## Multi-Factor Authentication (MFA)

Add an extra layer of security:

```python
import pyotp
from datetime import datetime, timedelta

class MFAService:
    def __init__(self):
        self.user_secrets = {}  # In production, use encrypted database
        self.backup_codes = {}
    
    def setup_mfa(self, user_id: str) -> dict:
        """
        Set up MFA for a user.
        
        Returns:
            Dictionary with secret and QR code URL
        """
        # Generate secret
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = secret
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        self.backup_codes[user_id] = set(backup_codes)
        
        # Create provisioning URI for QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_id,
            issuer_name="AI Agent Service"
        )
        
        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes
        }
    
    def verify_code(self, user_id: str, code: str) -> bool:
        """
        Verify a TOTP code.
        """
        if user_id not in self.user_secrets:
            return False
        
        # Check if it's a backup code
        if code in self.backup_codes.get(user_id, set()):
            self.backup_codes[user_id].remove(code)
            return True
        
        # Verify TOTP code
        totp = pyotp.TOTP(self.user_secrets[user_id])
        return totp.verify(code, valid_window=1)
```

## Implementing in FastAPI

Complete authentication and authorization flow:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional

app = FastAPI()
security = HTTPBearer()

# Services
auth_service = AzureADAuth()
authz_service = AuthorizationService()
mfa_service = MFAService()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Dependency to get and verify current user from token.
    """
    try:
        user_info = await auth_service.verify_token(credentials.credentials)
        return user_info
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

def require_permission(permission: Permission):
    """
    Dependency factory to require a specific permission.
    """
    async def permission_checker(user: dict = Depends(get_current_user)):
        if not authz_service.check_permission(user["user_id"], permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission.value}"
            )
        return user
    return permission_checker

# Protected endpoints
@app.post("/agent/process")
async def process_request(
    request: dict,
    user: dict = Depends(require_permission(Permission.USE_AGENT))
):
    """Process request with agent (requires USE_AGENT permission)."""
    return await agent.process(request, user_id=user["user_id"])

@app.get("/agent/config")
async def get_config(
    user: dict = Depends(require_permission(Permission.CONFIGURE_AGENT))
):
    """Get agent configuration (requires CONFIGURE_AGENT permission)."""
    return agent.get_config()

@app.post("/admin/users/{user_id}/role")
async def assign_role(
    user_id: str,
    role: str,
    admin: dict = Depends(require_permission(Permission.ADMIN))
):
    """Assign role to user (requires ADMIN permission)."""
    authz_service.assign_role(user_id, Role[role.upper()])
    return {"message": f"Role {role} assigned to user {user_id}"}
```

## Session Management

Implement secure session handling:

```python
import jwt
from datetime import datetime, timedelta
from typing import Optional

class SessionManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.active_sessions = {}
    
    def create_session(self, user_id: str, duration_minutes: int = 60) -> str:
        """
        Create a session token.
        """
        payload = {
            "user_id": user_id,
            "session_id": secrets.token_hex(16),
            "exp": datetime.utcnow() + timedelta(minutes=duration_minutes),
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        
        # Store session
        self.active_sessions[payload["session_id"]] = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        return token
    
    def verify_session(self, token: str) -> Optional[dict]:
        """
        Verify session token and return user information.
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            session_id = payload["session_id"]
            
            # Check if session is active
            if session_id not in self.active_sessions:
                return None
            
            # Update last activity
            self.active_sessions[session_id]["last_activity"] = datetime.utcnow()
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_session(self, token: str):
        """Revoke a session."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"],
                options={"verify_exp": False}
            )
            session_id = payload["session_id"]
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
        except:
            pass
```

## Best Practices

!!! tip "Authentication Best Practices"
    - Use strong, unique passwords with minimum complexity requirements
    - Implement MFA for all users, especially administrators
    - Use OAuth 2.0 / OpenID Connect for modern applications
    - Never store passwords in plain text
    - Implement account lockout after failed attempts
    - Use secure session management with proper timeouts

!!! warning "Common Pitfalls"
    - Don't implement your own cryptography
    - Don't store API keys in code or version control
    - Don't use weak or predictable secrets
    - Don't trust client-side authentication
    - Don't forget to validate tokens server-side

<div class="resource-links">

### 📚 Microsoft Learn Resources

- [Azure AD Authentication](https://learn.microsoft.com/azure/active-directory/develop/)

- [Managed Identity](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/)

- [Azure RBAC](https://learn.microsoft.com/azure/role-based-access-control/)

- [API Management Authentication](https://learn.microsoft.com/azure/api-management/api-management-authentication-policies)


### 📖 Additional Documentation

- [OAuth 2.0 Specification](https://oauth.net/2/)

- [OpenID Connect](https://openid.net/connect/)

- [JWT.io](https://jwt.io/)


</div>
