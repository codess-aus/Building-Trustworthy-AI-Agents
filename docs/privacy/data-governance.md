# Data Governance

<img src="../images/hero-privacy.svg" alt="Data Governance" class="hero-image" role="img" aria-label="Data Governance Hero Image">

## Overview

Data governance establishes policies, procedures, and standards for managing data throughout its lifecycle in your AI agent system.

## Data Classification

Classify data by sensitivity level:

```python
from enum import Enum

class DataClassification(Enum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4

class DataGovernance:
    def classify_data(self, data: dict) -> DataClassification:
        """Classify data based on content."""
        if self.contains_pii(data):
            return DataClassification.RESTRICTED
        elif self.contains_business_sensitive(data):
            return DataClassification.CONFIDENTIAL
        elif self.is_internal_only(data):
            return DataClassification.INTERNAL
        else:
            return DataClassification.PUBLIC

    def get_handling_requirements(
        self,
        classification: DataClassification
    ) -> dict:
        """Get data handling requirements by classification."""
        requirements = {
            DataClassification.PUBLIC: {
                "encryption_required": False,
                "access_control": "None",
                "retention_days": 365,
            },
            DataClassification.INTERNAL: {
                "encryption_required": True,
                "access_control": "Authenticated users",
                "retention_days": 730,
            },
            DataClassification.CONFIDENTIAL: {
                "encryption_required": True,
                "access_control": "Role-based",
                "retention_days": 2555,
                "audit_logging": True,
            },
            DataClassification.RESTRICTED: {
                "encryption_required": True,
                "encryption_type": "AES-256",
                "access_control": "Explicit authorization",
                "retention_days": 90,
                "audit_logging": True,
                "data_masking": True,
            }
        }
        return requirements[classification]
```

## Data Lifecycle Management

Manage data from creation to deletion:

```python
from datetime import datetime, timedelta

class DataLifecycle:
    """Manage data through its lifecycle."""

    STAGES = ['created', 'active', 'archived', 'deleted']

    async def transition_data(
        self,
        data_id: str,
        from_stage: str,
        to_stage: str
    ):
        """Transition data between lifecycle stages."""
        # Verify valid transition
        if not self.is_valid_transition(from_stage, to_stage):
            raise ValueError(f"Invalid transition: {from_stage} -> {to_stage}")

        # Apply stage-specific actions
        if to_stage == 'archived':
            await self.archive_data(data_id)
        elif to_stage == 'deleted':
            await self.delete_data(data_id)

        # Update metadata
        await self.update_lifecycle_stage(data_id, to_stage)

    async def auto_manage_lifecycle(self):
        """Automatically manage data lifecycle based on policies."""
        # Archive old inactive data
        cutoff_active = datetime.utcnow() - timedelta(days=90)
        old_data = await self.find_data_older_than(cutoff_active, 'active')

        for data in old_data:
            await self.transition_data(data.id, 'active', 'archived')

        # Delete very old archived data
        cutoff_archive = datetime.utcnow() - timedelta(days=365)
        old_archived = await self.find_data_older_than(cutoff_archive, 'archived')

        for data in old_archived:
            await self.transition_data(data.id, 'archived', 'deleted')
```

## Data Quality Management

Ensure data quality and integrity:

```python
class DataQuality:
    """Ensure data quality standards."""

    def validate_quality(self, data: dict) -> dict:
        """Validate data quality dimensions."""
        return {
            'completeness': self.check_completeness(data),
            'accuracy': self.check_accuracy(data),
            'consistency': self.check_consistency(data),
            'timeliness': self.check_timeliness(data),
            'validity': self.check_validity(data),
        }

    def check_completeness(self, data: dict) -> float:
        """Check if all required fields are present."""
        required_fields = ['user_id', 'timestamp', 'content']
        present = sum(1 for field in required_fields if field in data)
        return present / len(required_fields)

    def check_accuracy(self, data: dict) -> float:
        """Check data accuracy against known constraints."""
        checks_passed = 0
        total_checks = 0

        # Example: validate timestamp is reasonable
        if 'timestamp' in data:
            total_checks += 1
            try:
                ts = datetime.fromisoformat(data['timestamp'])
                if datetime(2020, 1, 1) < ts < datetime.utcnow():
                    checks_passed += 1
            except:
                pass

        return checks_passed / total_checks if total_checks > 0 else 1.0
```

## Data Lineage Tracking

Track data origins and transformations:

```python
class DataLineage:
    """Track data lineage for auditability."""

    def __init__(self):
        self.lineage_graph = {}

    def record_data_origin(
        self,
        data_id: str,
        source: str,
        collection_method: str
    ):
        """Record where data originated."""
        self.lineage_graph[data_id] = {
            'origin': {
                'source': source,
                'method': collection_method,
                'timestamp': datetime.utcnow().isoformat(),
            },
            'transformations': [],
            'destinations': []
        }

    def record_transformation(
        self,
        data_id: str,
        transformation: str,
        output_data_id: str
    ):
        """Record data transformation."""
        if data_id in self.lineage_graph:
            self.lineage_graph[data_id]['transformations'].append({
                'type': transformation,
                'output': output_data_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

    def get_lineage(self, data_id: str) -> dict:
        """Get complete lineage for a data item."""
        return self.lineage_graph.get(data_id, {})
```

## Data Access Controls

Implement fine-grained access controls:

```python
class DataAccessControl:
    """Control access to data based on policies."""

    def __init__(self):
        self.access_policies = {}

    def create_policy(
        self,
        data_id: str,
        allowed_users: list,
        allowed_roles: list,
        conditions: dict
    ):
        """Create access control policy for data."""
        self.access_policies[data_id] = {
            'allowed_users': set(allowed_users),
            'allowed_roles': set(allowed_roles),
            'conditions': conditions,
            'created_at': datetime.utcnow(),
        }

    def check_access(
        self,
        user_id: str,
        user_roles: list,
        data_id: str,
        operation: str
    ) -> bool:
        """Check if user can access data."""
        if data_id not in self.access_policies:
            return False

        policy = self.access_policies[data_id]

        # Check user
        if user_id in policy['allowed_users']:
            return True

        # Check roles
        if any(role in policy['allowed_roles'] for role in user_roles):
            return True

        # Check conditions
        if self.evaluate_conditions(policy['conditions'], user_id, operation):
            return True

        return False
```

## Data Catalog

Maintain a comprehensive data catalog:

```python
class DataCatalog:
    """Catalog of all data assets."""

    def __init__(self):
        self.catalog = {}

    def register_dataset(
        self,
        dataset_id: str,
        metadata: dict
    ):
        """Register a dataset in the catalog."""
        self.catalog[dataset_id] = {
            'id': dataset_id,
            'name': metadata.get('name'),
            'description': metadata.get('description'),
            'owner': metadata.get('owner'),
            'classification': metadata.get('classification'),
            'schema': metadata.get('schema'),
            'location': metadata.get('location'),
            'created_at': datetime.utcnow(),
            'last_updated': datetime.utcnow(),
            'tags': metadata.get('tags', []),
            'quality_score': None,
        }

    def search_catalog(self, query: str, filters: dict = None) -> list:
        """Search the data catalog."""
        results = []

        for dataset_id, metadata in self.catalog.items():
            # Search in name and description
            if (query.lower() in metadata['name'].lower() or
                query.lower() in metadata.get('description', '').lower()):

                # Apply filters
                if filters:
                    if not self.matches_filters(metadata, filters):
                        continue

                results.append(metadata)

        return results
```

<div class="resource-links">
<h3>📚 Microsoft Learn Resources</h3>
<ul>
<li><a href="https://learn.microsoft.com/azure/purview/" target="_blank" rel="noopener">Azure Purview Data Governance</a></li>
<li><a href="https://learn.microsoft.com/azure/information-protection/what-is-information-protection" target="_blank" rel="noopener">Data Classification in Azure</a></li>
<li><a href="https://learn.microsoft.com/azure/data-catalog/" target="_blank" rel="noopener">Azure Data Catalog</a></li>
</ul>
<h3>📖 Additional Documentation</h3>
<ul>
<li><a href="https://www.dama.org/cpages/body-of-knowledge" target="_blank" rel="noopener">DAMA DMBOK Framework</a></li>
<li><a href="https://docs.microsoft.com/azure/architecture/data-guide/" target="_blank" rel="noopener">Data Governance Best Practices</a></li>
</ul>
</div>
