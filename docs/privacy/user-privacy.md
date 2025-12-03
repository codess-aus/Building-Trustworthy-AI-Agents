# User Privacy

<img src="../images/hero-privacy.svg" alt="User Privacy" class="hero-image" role="img" aria-label="User Privacy Hero Image">

## User Privacy Rights

Implement user privacy rights as required by GDPR, CCPA, and other regulations.

## Right to Access

Users can request their data:

```python
from fastapi import FastAPI, Depends

app = FastAPI()

class UserPrivacyService:
    async def handle_access_request(self, user_id: str) -> dict:
        """Handle user's right to access their data."""
        user_data = {
            'personal_info': await self.get_user_profile(user_id),
            'conversations': await self.get_conversations(user_id),
            'preferences': await self.get_preferences(user_id),
            'consent_history': await self.get_consents(user_id),
            'access_logs': await self.get_access_logs(user_id),
        }
        
        return {
            'user_id': user_id,
            'export_date': datetime.utcnow().isoformat(),
            'format': 'JSON',
            'data': user_data
        }

@app.get("/privacy/my-data")
async def get_my_data(user_id: str = Depends(get_current_user)):
    """Endpoint for users to access their data."""
    service = UserPrivacyService()
    return await service.handle_access_request(user_id)
```

## Right to Deletion

Implement complete data deletion:

```python
class DataDeletionService:
    async def delete_user_data(self, user_id: str):
        """Completely delete user data (Right to be Forgotten)."""
        deletion_tasks = [
            self.delete_from_database(user_id),
            self.delete_from_cache(user_id),
            self.delete_from_backups(user_id),
            self.delete_from_analytics(user_id),
            self.remove_from_ml_dataset(user_id),
        ]
        
        results = await asyncio.gather(*deletion_tasks, return_exceptions=True)
        
        # Verify all deletions succeeded
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                raise DeletionError(f"Failed to delete from location {i}")
        
        # Log deletion
        await self.log_deletion(user_id)
        
        return {
            'status': 'completed',
            'deleted_at': datetime.utcnow().isoformat(),
            'verification_id': self.generate_verification_id()
        }
    
    async def anonymize_instead_of_delete(self, user_id: str):
        """
        Anonymize data when deletion would break referential integrity.
        """
        # Replace user_id with anonymous identifier
        anon_id = self.generate_anonymous_id()
        
        # Anonymize data
        await self.replace_user_id(user_id, anon_id)
        await self.remove_identifying_information(anon_id)
        
        return anon_id

@app.delete("/privacy/delete-my-data")
async def delete_my_data(user_id: str = Depends(get_current_user)):
    """Endpoint for users to delete their data."""
    service = DataDeletionService()
    return await service.delete_user_data(user_id)
```

## Consent Management

Manage user consent for data processing:

```python
class ConsentManagement:
    def __init__(self):
        self.consent_store = {}
    
    async def record_consent(
        self,
        user_id: str,
        purpose: str,
        granted: bool,
        consent_text: str
    ):
        """Record user consent."""
        consent_id = f"{user_id}:{purpose}:{datetime.utcnow().isoformat()}"
        
        self.consent_store[consent_id] = {
            'user_id': user_id,
            'purpose': purpose,
            'granted': granted,
            'timestamp': datetime.utcnow(),
            'consent_text': consent_text,
            'ip_address': self.get_user_ip(),
            'version': '1.0',
        }
        
        # Update active consent
        await self.update_active_consent(user_id, purpose, granted)
    
    async def check_consent(self, user_id: str, purpose: str) -> bool:
        """Check if user has given consent for purpose."""
        active_consents = await self.get_active_consents(user_id)
        return active_consents.get(purpose, False)
    
    async def withdraw_consent(self, user_id: str, purpose: str):
        """Allow user to withdraw consent."""
        await self.record_consent(
            user_id,
            purpose,
            granted=False,
            consent_text="User withdrew consent"
        )
        
        # Stop processing for this purpose
        await self.stop_processing(user_id, purpose)

@app.post("/privacy/consent")
async def manage_consent(
    consent_request: dict,
    user_id: str = Depends(get_current_user)
):
    """Endpoint for managing consent."""
    service = ConsentManagement()
    
    if consent_request['action'] == 'grant':
        await service.record_consent(
            user_id,
            consent_request['purpose'],
            granted=True,
            consent_text=consent_request['consent_text']
        )
    elif consent_request['action'] == 'withdraw':
        await service.withdraw_consent(user_id, consent_request['purpose'])
    
    return {'status': 'success'}
```

## Privacy Dashboard

Provide users with a privacy dashboard:

```python
@app.get("/privacy/dashboard")
async def privacy_dashboard(user_id: str = Depends(get_current_user)):
    """Privacy dashboard showing user's privacy status."""
    service = UserPrivacyService()
    consent_service = ConsentManagement()
    
    dashboard = {
        'data_summary': {
            'conversations_count': await service.count_conversations(user_id),
            'data_size_mb': await service.calculate_data_size(user_id),
            'oldest_data': await service.get_oldest_data_date(user_id),
        },
        'active_consents': await consent_service.get_active_consents(user_id),
        'data_retention': {
            'policy': '90 days for conversations',
            'next_deletion': await service.get_next_deletion_date(user_id),
        },
        'privacy_settings': await service.get_privacy_settings(user_id),
        'data_sharing': await service.get_data_sharing_status(user_id),
        'actions_available': [
            {
                'action': 'export_data',
                'description': 'Download all your data',
                'endpoint': '/privacy/my-data'
            },
            {
                'action': 'delete_data',
                'description': 'Permanently delete your account and data',
                'endpoint': '/privacy/delete-my-data'
            },
            {
                'action': 'manage_consent',
                'description': 'Change your consent preferences',
                'endpoint': '/privacy/consent'
            }
        ]
    }
    
    return dashboard
```

## Data Portability

Enable users to export their data in standard formats:

```python
class DataPortability:
    async def export_data(
        self,
        user_id: str,
        format: str = 'json'
    ) -> bytes:
        """Export user data in portable format."""
        user_data = await self.collect_user_data(user_id)
        
        if format == 'json':
            return self.export_as_json(user_data)
        elif format == 'csv':
            return self.export_as_csv(user_data)
        elif format == 'xml':
            return self.export_as_xml(user_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def export_as_json(self, data: dict) -> bytes:
        """Export data as JSON."""
        import json
        return json.dumps(data, indent=2, default=str).encode('utf-8')
    
    def export_as_csv(self, data: dict) -> bytes:
        """Export data as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        
        # Flatten nested structure for CSV
        flat_data = self.flatten_dict(data)
        
        writer = csv.DictWriter(output, fieldnames=flat_data.keys())
        writer.writeheader()
        writer.writerow(flat_data)
        
        return output.getvalue().encode('utf-8')

@app.get("/privacy/export")
async def export_user_data(
    format: str = 'json',
    user_id: str = Depends(get_current_user)
):
    """Export user data in requested format."""
    from fastapi.responses import Response
    
    service = DataPortability()
    data = await service.export_data(user_id, format)
    
    media_types = {
        'json': 'application/json',
        'csv': 'text/csv',
        'xml': 'application/xml',
    }
    
    return Response(
        content=data,
        media_type=media_types[format],
        headers={
            'Content-Disposition': f'attachment; filename=user_data.{format}'
        }
    )
```

## Privacy-Preserving Analytics

Collect analytics while preserving privacy:

```python
import numpy as np

class PrivacyPreservingAnalytics:
    def __init__(self, epsilon: float = 1.0):
        self.epsilon = epsilon  # Privacy budget
    
    async def collect_usage_metrics(self, user_id: str, event: dict):
        """Collect anonymized usage metrics."""
        # Remove identifying information
        anonymous_event = {
            'user_hash': self.hash_user_id(user_id),
            'event_type': event['type'],
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': self.hash_session_id(event.get('session_id')),
            # Don't include actual content
        }
        
        await self.store_analytics(anonymous_event)
    
    def hash_user_id(self, user_id: str) -> str:
        """Create anonymous hash of user ID."""
        import hashlib
        return hashlib.sha256(f"{user_id}:salt".encode()).hexdigest()[:16]
    
    async def aggregate_with_privacy(
        self,
        metric: str,
        aggregation: str = 'count'
    ) -> float:
        """Aggregate metrics with differential privacy."""
        true_value = await self.calculate_metric(metric, aggregation)
        
        # Add noise for differential privacy
        noise_scale = 1.0 / self.epsilon
        noise = np.random.laplace(0, noise_scale)
        
        return max(0, true_value + noise)
```

## Privacy Notices and Communications

```python
class PrivacyNotifications:
    async def notify_privacy_policy_change(self, user_id: str):
        """Notify user of privacy policy changes."""
        await self.send_notification(
            user_id,
            subject="Privacy Policy Update",
            message="""
            We've updated our privacy policy. Key changes:
            - Extended data retention period for audit logs
            - New data processing partner added
            
            Please review: https://example.com/privacy
            
            You can object to these changes or withdraw consent at:
            https://example.com/privacy/dashboard
            """
        )
    
    async def notify_data_breach(self, user_id: str, breach_details: dict):
        """Notify user of data breach (72-hour requirement)."""
        await self.send_notification(
            user_id,
            subject="Important: Data Breach Notification",
            message=f"""
            We're writing to inform you of a data security incident.
            
            What happened: {breach_details['description']}
            When: {breach_details['occurred_at']}
            Data affected: {breach_details['affected_data']}
            
            Actions we've taken: {breach_details['actions_taken']}
            
            Actions you should take: {breach_details['user_actions']}
            
            For more information: {breach_details['contact_info']}
            """,
            priority='high'
        )
```

<div class="resource-links">

### 📚 Microsoft Learn Resources

- [Privacy in Azure](https://learn.microsoft.com/azure/compliance/offerings/)

- [User Rights Management](https://learn.microsoft.com/azure/active-directory/identity-protection/)

- [Consent Management](https://learn.microsoft.com/azure/active-directory-b2c/custom-policy-overview)


### 📖 Additional Documentation

- [GDPR User Rights](https://gdpr.eu/right-to-be-forgotten/)

- [CCPA Consumer Rights](https://oag.ca.gov/privacy/ccpa)


</div>
