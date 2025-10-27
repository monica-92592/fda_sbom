# Week 1-2 Implementation Plan: Foundation & Core Engine

## Overview
This document provides detailed step-by-step instructions for implementing the foundation and core engine components of the FDA-compliant SBOM generator during weeks 1-2.

---

## Task 1: Initialize Project Structure and Development Environment

### Step 1.1: Create Project Directory Structure
```bash
# Create main project directories
mkdir -p fda-sbom-generator/{backend,frontend,docs,scripts,tests,deployment}
mkdir -p fda-sbom-generator/backend/{app,core,models,services,utils,tests}
mkdir -p fda-sbom-generator/frontend/{src,public,tests}
mkdir -p fda-sbom-generator/docs/{api,architecture,compliance}
mkdir -p fda-sbom-generator/scripts/{setup,deploy,maintenance}
mkdir -p fda-sbom-generator/tests/{unit,integration,e2e}
mkdir -p fda-sbom-generator/deployment/{docker,kubernetes,terraform}
```

### Step 1.2: Initialize Backend Python Project
```bash
cd fda-sbom-generator/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Create requirements files
touch requirements.txt requirements-dev.txt requirements-test.txt

# Initialize git repository (if not already done)
git init
```

### Step 1.3: Set Up Backend Dependencies
```bash
# Install core dependencies
pip install fastapi uvicorn sqlalchemy alembic psycopg2-binary
pip install pydantic python-multipart python-jose[cryptography]
pip install passlib[bcrypt] celery redis python-dotenv

# Install development dependencies
pip install pytest pytest-asyncio pytest-cov black isort flake8 mypy
pip install pre-commit bandit safety

# Install SBOM and security dependencies
pip install spdx-tools cyclonedx-bom spdx-utils
pip install requests aiohttp beautifulsoup4 lxml
pip install cryptography pycryptodome
```

### Step 1.4: Initialize Frontend React Project
```bash
cd ../frontend

# Create React app with TypeScript
npx create-react-app . --template typescript
npm install @mui/material @emotion/react @emotion/styled
npm install @mui/icons-material @mui/x-data-grid
npm install axios react-router-dom @reduxjs/toolkit react-redux
npm install recharts react-query @tanstack/react-query
npm install @testing-library/react @testing-library/jest-dom
npm install --save-dev @types/node @types/react @types/react-dom
```

### Step 1.5: Create Configuration Files
```bash
# Backend configuration
cat > backend/.env.example << EOF
DATABASE_URL=postgresql://user:password@localhost:5432/fda_sbom
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
CVE_API_KEY=your-cve-api-key
NVD_API_KEY=your-nvd-api-key
EOF

# Frontend configuration
cat > frontend/.env.example << EOF
REACT_APP_API_URL=http://localhost:8000
REACT_APP_VERSION=1.0.0
EOF
```

---

## Task 2: Set Up CI/CD Pipeline with GitHub Actions

### Step 2.1: Create GitHub Actions Workflow Directory
```bash
mkdir -p .github/workflows
```

### Step 2.2: Create Main CI/CD Workflow
```bash
cat > .github/workflows/ci-cd.yml << 'EOF'
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd backend
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run linting
      run: |
        cd backend
        flake8 app/
        black --check app/
        isort --check-only app/
    
    - name: Run type checking
      run: |
        cd backend
        mypy app/
    
    - name: Run security checks
      run: |
        cd backend
        bandit -r app/
        safety check
    
    - name: Run tests
      run: |
        cd backend
        pytest tests/ --cov=app --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: backend/coverage.xml

  test-frontend:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: frontend/package-lock.json
    
    - name: Install dependencies
      run: |
        cd frontend
        npm ci
    
    - name: Run linting
      run: |
        cd frontend
        npm run lint
    
    - name: Run tests
      run: |
        cd frontend
        npm test -- --coverage --watchAll=false
    
    - name: Build
      run: |
        cd frontend
        npm run build

  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  deploy:
    needs: [test-backend, test-frontend, security-scan]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # Add deployment commands here
EOF
```

### Step 2.3: Create Pre-commit Configuration
```bash
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
EOF
```

---

## Task 3: Implement Basic SBOM Parsing for Common Package Managers

### Step 3.1: Create Package Manager Base Classes
```bash
mkdir -p backend/app/scanners
```

```python
# backend/app/scanners/base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class PackageInfo:
    name: str
    version: str
    license: str
    homepage: str
    description: str
    dependencies: List[str]
    checksums: Dict[str, str]

class PackageManagerScanner(ABC):
    """Base class for package manager scanners"""
    
    def __init__(self):
        self.name = self.get_name()
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the name of the package manager"""
        pass
    
    @abstractmethod
    def detect_project(self, project_path: str) -> bool:
        """Detect if this package manager is used in the project"""
        pass
    
    @abstractmethod
    def scan_dependencies(self, project_path: str) -> List[PackageInfo]:
        """Scan and return package dependencies"""
        pass
    
    @abstractmethod
    def get_lockfile_path(self, project_path: str) -> str:
        """Return the path to the lockfile"""
        pass
```

### Step 3.2: Implement NPM/Yarn Scanner
```python
# backend/app/scanners/npm_scanner.py
import json
import os
import subprocess
from typing import List, Dict, Any
from .base import PackageManagerScanner, PackageInfo

class NpmScanner(PackageManagerScanner):
    def get_name(self) -> str:
        return "npm"
    
    def detect_project(self, project_path: str) -> bool:
        """Detect if this is an npm project"""
        package_json = os.path.join(project_path, "package.json")
        package_lock = os.path.join(project_path, "package-lock.json")
        return os.path.exists(package_json) or os.path.exists(package_lock)
    
    def scan_dependencies(self, project_path: str) -> List[PackageInfo]:
        """Scan npm dependencies"""
        packages = []
        
        # Read package.json
        package_json_path = os.path.join(project_path, "package.json")
        if os.path.exists(package_json_path):
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
            
            # Get direct dependencies
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            
            for name, version in all_deps.items():
                package_info = self._get_package_info(name, version, project_path)
                if package_info:
                    packages.append(package_info)
        
        return packages
    
    def _get_package_info(self, name: str, version: str, project_path: str) -> PackageInfo:
        """Get detailed package information"""
        try:
            # Use npm view to get package details
            result = subprocess.run(
                ['npm', 'view', name, '--json'],
                capture_output=True,
                text=True,
                cwd=project_path
            )
            
            if result.returncode == 0:
                package_data = json.loads(result.stdout)
                
                return PackageInfo(
                    name=name,
                    version=version,
                    license=package_data.get('license', 'Unknown'),
                    homepage=package_data.get('homepage', ''),
                    description=package_data.get('description', ''),
                    dependencies=list(package_data.get('dependencies', {}).keys()),
                    checksums={}  # Will be populated later
                )
        except Exception as e:
            print(f"Error getting package info for {name}: {e}")
        
        return None
    
    def get_lockfile_path(self, project_path: str) -> str:
        """Return the path to package-lock.json"""
        return os.path.join(project_path, "package-lock.json")
```

### Step 3.3: Implement Python Pip/Conda Scanner
```python
# backend/app/scanners/pip_scanner.py
import os
import subprocess
import json
from typing import List, Dict, Any
from .base import PackageManagerScanner, PackageInfo

class PipScanner(PackageManagerScanner):
    def get_name(self) -> str:
        return "pip"
    
    def detect_project(self, project_path: str) -> bool:
        """Detect if this is a Python project"""
        requirements_files = [
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile"
        ]
        
        for req_file in requirements_files:
            if os.path.exists(os.path.join(project_path, req_file)):
                return True
        return False
    
    def scan_dependencies(self, project_path: str) -> List[PackageInfo]:
        """Scan pip dependencies"""
        packages = []
        
        # Check for requirements.txt
        requirements_path = os.path.join(project_path, "requirements.txt")
        if os.path.exists(requirements_path):
            packages.extend(self._parse_requirements_file(requirements_path))
        
        # Check for pyproject.toml
        pyproject_path = os.path.join(project_path, "pyproject.toml")
        if os.path.exists(pyproject_path):
            packages.extend(self._parse_pyproject_toml(pyproject_path))
        
        return packages
    
    def _parse_requirements_file(self, requirements_path: str) -> List[PackageInfo]:
        """Parse requirements.txt file"""
        packages = []
        
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package name and version
                    if '==' in line:
                        name, version = line.split('==', 1)
                    elif '>=' in line:
                        name, version = line.split('>=', 1)
                    else:
                        name = line
                        version = "latest"
                    
                    package_info = self._get_package_info(name.strip(), version.strip())
                    if package_info:
                        packages.append(package_info)
        
        return packages
    
    def _get_package_info(self, name: str, version: str) -> PackageInfo:
        """Get package information from PyPI"""
        try:
            # Use pip show to get package details
            result = subprocess.run(
                ['pip', 'show', name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                package_data = {}
                
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        package_data[key.strip()] = value.strip()
                
                return PackageInfo(
                    name=name,
                    version=version,
                    license=package_data.get('License', 'Unknown'),
                    homepage=package_data.get('Home-page', ''),
                    description=package_data.get('Summary', ''),
                    dependencies=[],  # Will be populated from Requires field
                    checksums={}
                )
        except Exception as e:
            print(f"Error getting package info for {name}: {e}")
        
        return None
    
    def get_lockfile_path(self, project_path: str) -> str:
        """Return the path to requirements.txt"""
        return os.path.join(project_path, "requirements.txt")
```

### Step 3.4: Implement Maven/Gradle Scanner
```python
# backend/app/scanners/maven_scanner.py
import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from .base import PackageManagerScanner, PackageInfo

class MavenScanner(PackageManagerScanner):
    def get_name(self) -> str:
        return "maven"
    
    def detect_project(self, project_path: str) -> bool:
        """Detect if this is a Maven project"""
        pom_path = os.path.join(project_path, "pom.xml")
        return os.path.exists(pom_path)
    
    def scan_dependencies(self, project_path: str) -> List[PackageInfo]:
        """Scan Maven dependencies"""
        packages = []
        
        pom_path = os.path.join(project_path, "pom.xml")
        if os.path.exists(pom_path):
            packages.extend(self._parse_pom_file(pom_path))
        
        return packages
    
    def _parse_pom_file(self, pom_path: str) -> List[PackageInfo]:
        """Parse pom.xml file"""
        packages = []
        
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            
            # Handle namespace
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Get dependencies
            dependencies = root.findall('.//maven:dependency', ns)
            
            for dep in dependencies:
                group_id = dep.find('maven:groupId', ns)
                artifact_id = dep.find('maven:artifactId', ns)
                version = dep.find('maven:version', ns)
                
                if group_id is not None and artifact_id is not None:
                    name = f"{group_id.text}:{artifact_id.text}"
                    version_text = version.text if version is not None else "unknown"
                    
                    package_info = PackageInfo(
                        name=name,
                        version=version_text,
                        license="Unknown",  # Will be enriched later
                        homepage="",
                        description="",
                        dependencies=[],
                        checksums={}
                    )
                    packages.append(package_info)
        
        except Exception as e:
            print(f"Error parsing pom.xml: {e}")
        
        return packages
    
    def get_lockfile_path(self, project_path: str) -> str:
        """Return the path to pom.xml"""
        return os.path.join(project_path, "pom.xml")
```

### Step 3.5: Create Scanner Registry
```python
# backend/app/scanners/registry.py
from typing import List, Dict, Any
from .base import PackageManagerScanner, PackageInfo
from .npm_scanner import NpmScanner
from .pip_scanner import PipScanner
from .maven_scanner import MavenScanner

class ScannerRegistry:
    """Registry for all package manager scanners"""
    
    def __init__(self):
        self.scanners = [
            NpmScanner(),
            PipScanner(),
            MavenScanner(),
            # Add more scanners here
        ]
    
    def scan_project(self, project_path: str) -> List[PackageInfo]:
        """Scan project with all applicable scanners"""
        all_packages = []
        
        for scanner in self.scanners:
            if scanner.detect_project(project_path):
                print(f"Detected {scanner.get_name()} project")
                packages = scanner.scan_dependencies(project_path)
                all_packages.extend(packages)
        
        return all_packages
    
    def get_applicable_scanners(self, project_path: str) -> List[PackageManagerScanner]:
        """Get list of scanners applicable to the project"""
        applicable = []
        
        for scanner in self.scanners:
            if scanner.detect_project(project_path):
                applicable.append(scanner)
        
        return applicable
```

---

## Task 4: Create Core SBOM Data Models

### Step 4.1: Create SPDX Data Models
```python
# backend/app/models/spdx.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class SPDXLicenseExpression:
    """SPDX License Expression"""
    def __init__(self, expression: str):
        self.expression = expression

class SPDXRelationshipType(Enum):
    DESCRIBES = "DESCRIBES"
    DESCRIBED_BY = "DESCRIBED_BY"
    CONTAINS = "CONTAINS"
    CONTAINED_BY = "CONTAINED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    DEPENDENCY_OF = "DEPENDENCY_OF"
    BUILD_TOOL_OF = "BUILD_TOOL_OF"
    BUILD_DEPENDENCY_OF = "BUILD_DEPENDENCY_OF"
    DEV_TOOL_OF = "DEV_TOOL_OF"
    DEV_DEPENDENCY_OF = "DEV_DEPENDENCY_OF"
    TEST_OF = "TEST_OF"
    TEST_TOOL_OF = "TEST_TOOL_OF"
    TEST_DEPENDENCY_OF = "TEST_DEPENDENCY_OF"
    RUNTIME_DEPENDENCY_OF = "RUNTIME_DEPENDENCY_OF"
    EXAMPLE_OF = "EXAMPLE_OF"
    GENERATES = "GENERATES"
    GENERATED_FROM = "GENERATED_FROM"
    ANCESTOR_OF = "ANCESTOR_OF"
    DESCENDANT_OF = "DESCENDANT_OF"
    VARIANT_OF = "VARIANT_OF"
    DISTRIBUTION_ARTIFACT = "DISTRIBUTION_ARTIFACT"
    PATCH_FOR = "PATCH_FOR"
    PATCH_APPLIED = "PATCH_APPLIED"
    COPY_OF = "COPY_OF"
    FILE_ADDED = "FILE_ADDED"
    FILE_DELETED = "FILE_DELETED"
    FILE_MODIFIED = "FILE_MODIFIED"
    EXPANDED_FROM_ARCHIVE = "EXPANDED_FROM_ARCHIVE"
    DYNAMIC_LINK = "DYNAMIC_LINK"
    STATIC_LINK = "STATIC_LINK"
    DATA_FILE_OF = "DATA_FILE_OF"
    TEST_CASE_OF = "TEST_CASE_OF"
    OTHER = "OTHER"

@dataclass
class SPDXChecksum:
    algorithm: str  # SHA1, SHA224, SHA256, SHA384, SHA512, MD2, MD4, MD5, MD6
    checksum_value: str

@dataclass
class SPDXExternalRef:
    reference_category: str  # SECURITY, PACKAGE-MANAGER, PERSISTENT-ID, OTHER
    reference_type: str
    reference_locator: str
    comment: Optional[str] = None

@dataclass
class SPDXPackage:
    spdx_id: str
    name: str
    version_info: Optional[str] = None
    download_location: Optional[str] = None
    files_analyzed: bool = True
    license_concluded: Optional[str] = None
    license_declared: Optional[str] = None
    copyright_text: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    comment: Optional[str] = None
    external_refs: List[SPDXExternalRef] = field(default_factory=list)
    checksums: List[SPDXChecksum] = field(default_factory=list)
    homepage: Optional[str] = None
    source_info: Optional[str] = None
    originator: Optional[str] = None
    supplier: Optional[str] = None
    release_date: Optional[str] = None
    built_date: Optional[str] = None
    valid_until_date: Optional[str] = None

@dataclass
class SPDXRelationship:
    spdx_element_id: str
    relationship_type: SPDXRelationshipType
    related_spdx_element: str
    comment: Optional[str] = None

@dataclass
class SPDXDocument:
    spdx_version: str = "SPDX-2.3"
    data_license: str = "CC0-1.0"
    spdx_id: str = "SPDXRef-DOCUMENT"
    name: str = ""
    document_namespace: str = ""
    creator: str = ""
    created: str = ""
    creator_comment: Optional[str] = None
    document_comment: Optional[str] = None
    packages: List[SPDXPackage] = field(default_factory=list)
    relationships: List[SPDXRelationship] = field(default_factory=list)
    external_document_refs: List[Dict[str, str]] = field(default_factory=list)
    extracted_licensing_info: List[Dict[str, Any]] = field(default_factory=list)
```

### Step 4.2: Create CycloneDX Data Models
```python
# backend/app/models/cyclonedx.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class CycloneDXComponentType(Enum):
    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"

class CycloneDXScope(Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    EXCLUDED = "excluded"

@dataclass
class CycloneDXHash:
    alg: str  # MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3
    content: str

@dataclass
class CycloneDXExternalReference:
    type: str  # vcs, issue-tracker, website, advisories, bom, mailing-list, social, chat, documentation, support, distribution, license, build-meta, build-system, other
    url: str
    comment: Optional[str] = None
    hashes: List[CycloneDXHash] = field(default_factory=list)

@dataclass
class CycloneDXLicense:
    id: Optional[str] = None
    name: Optional[str] = None
    text: Optional[str] = None
    url: Optional[str] = None
    expression: Optional[str] = None

@dataclass
class CycloneDXComponent:
    type: CycloneDXComponentType
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    group: Optional[str] = None
    scope: Optional[CycloneDXScope] = None
    hashes: List[CycloneDXHash] = field(default_factory=list)
    licenses: List[CycloneDXLicense] = field(default_factory=list)
    copyright: Optional[str] = None
    cpe: Optional[str] = None
    purl: Optional[str] = None
    swid: Optional[Dict[str, Any]] = None
    external_references: List[CycloneDXExternalReference] = field(default_factory=list)
    properties: List[Dict[str, str]] = field(default_factory=list)
    components: List['CycloneDXComponent'] = field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None
    release_notes: Optional[Dict[str, Any]] = None

@dataclass
class CycloneDXMetadata:
    timestamp: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)
    authors: List[Dict[str, str]] = field(default_factory=list)
    component: Optional[CycloneDXComponent] = None
    manufacture: Optional[Dict[str, str]] = None
    supplier: Optional[Dict[str, str]] = None
    licenses: List[CycloneDXLicense] = field(default_factory=list)
    properties: List[Dict[str, str]] = field(default_factory=list)
    lifecycle: Optional[str] = None
    pedigree: Optional[Dict[str, Any]] = None

@dataclass
class CycloneDXBOM:
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    serial_number: Optional[str] = None
    version: int = 1
    metadata: Optional[CycloneDXMetadata] = None
    components: List[CycloneDXComponent] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    external_references: List[CycloneDXExternalReference] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    compositions: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    annotations: List[Dict[str, Any]] = field(default_factory=list)
    formulation: Optional[Dict[str, Any]] = None
```

---

## Task 5: Implement Basic Vulnerability Scanning Integration

### Step 5.1: Create Vulnerability Data Models
```python
# backend/app/models/vulnerability.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

@dataclass
class CVSSScore:
    version: str  # "2.0", "3.0", "3.1", "4.0"
    vector_string: str
    base_score: float
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

@dataclass
class VulnerabilityReference:
    url: str
    source: str
    tags: List[str] = field(default_factory=list)

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: VulnerabilitySeverity
    cvss_scores: List[CVSSScore] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    references: List[VulnerabilityReference] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    tags: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None
    remediation: Optional[str] = None
    workaround: Optional[str] = None

@dataclass
class ComponentVulnerability:
    component_id: str
    component_name: str
    component_version: str
    vulnerability: Vulnerability
    affected: bool = True
    fixed_in_version: Optional[str] = None
    mitigation_applied: Optional[str] = None
    risk_score: Optional[float] = None
    business_impact: Optional[str] = None
```

### Step 5.2: Create CVE API Client
```python
# backend/app/services/cve_client.py
import aiohttp
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime
import json

class CVEClient:
    """Client for interacting with CVE databases"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for CVEs by keyword"""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit
        }
        
        if self.api_key:
            params["apiKey"] = self.api_key
        
        async with self.session.get(self.base_url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("vulnerabilities", [])
            else:
                print(f"Error fetching CVEs: {response.status}")
                return []
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific CVE"""
        url = f"{self.base_url}/{cve_id}"
        params = {}
        
        if self.api_key:
            params["apiKey"] = self.api_key
        
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("vulnerabilities", [{}])[0]
            else:
                print(f"Error fetching CVE {cve_id}: {response.status}")
                return None
    
    async def get_cves_by_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """Get CVEs for a specific CPE"""
        params = {
            "cpeName": cpe
        }
        
        if self.api_key:
            params["apiKey"] = self.api_key
        
        async with self.session.get(self.base_url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("vulnerabilities", [])
            else:
                print(f"Error fetching CVEs for CPE {cpe}: {response.status}")
                return []
```

### Step 5.3: Create Vulnerability Scanner
```python
# backend/app/services/vulnerability_scanner.py
from typing import List, Dict, Optional, Any
from ..models.vulnerability import Vulnerability, ComponentVulnerability, VulnerabilitySeverity
from ..models.spdx import SPDXPackage
from .cve_client import CVEClient
import asyncio

class VulnerabilityScanner:
    """Scanner for identifying vulnerabilities in components"""
    
    def __init__(self, cve_api_key: Optional[str] = None):
        self.cve_client = CVEClient(cve_api_key)
    
    async def scan_component(self, component: SPDXPackage) -> List[ComponentVulnerability]:
        """Scan a single component for vulnerabilities"""
        vulnerabilities = []
        
        # Search for CVEs by component name
        async with self.cve_client as client:
            cves = await client.search_cves(component.name)
            
            for cve_data in cves:
                vulnerability = self._parse_cve_data(cve_data)
                if vulnerability and self._is_component_affected(component, vulnerability):
                    comp_vuln = ComponentVulnerability(
                        component_id=component.spdx_id,
                        component_name=component.name,
                        component_version=component.version_info or "unknown",
                        vulnerability=vulnerability
                    )
                    vulnerabilities.append(comp_vuln)
        
        return vulnerabilities
    
    async def scan_components(self, components: List[SPDXPackage]) -> List[ComponentVulnerability]:
        """Scan multiple components for vulnerabilities"""
        all_vulnerabilities = []
        
        # Process components in parallel
        tasks = [self.scan_component(component) for component in components]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            all_vulnerabilities.extend(result)
        
        return all_vulnerabilities
    
    def _parse_cve_data(self, cve_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse CVE data into Vulnerability object"""
        try:
            cve_id = cve_data.get("id", "")
            descriptions = cve_data.get("descriptions", [])
            description = descriptions[0].get("value", "") if descriptions else ""
            
            # Get CVSS scores
            cvss_scores = []
            metrics = cve_data.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_scores.append({
                    "version": "3.1",
                    "vector_string": cvss_data.get("vectorString", ""),
                    "base_score": cvss_data.get("baseScore", 0.0),
                    "base_severity": cvss_data.get("baseSeverity", "UNKNOWN")
                })
            
            # Determine severity
            severity = VulnerabilitySeverity.LOW
            if cvss_scores:
                base_severity = cvss_scores[0].get("base_severity", "UNKNOWN")
                severity_map = {
                    "CRITICAL": VulnerabilitySeverity.CRITICAL,
                    "HIGH": VulnerabilitySeverity.HIGH,
                    "MEDIUM": VulnerabilitySeverity.MEDIUM,
                    "LOW": VulnerabilitySeverity.LOW
                }
                severity = severity_map.get(base_severity, VulnerabilitySeverity.LOW)
            
            return Vulnerability(
                cve_id=cve_id,
                description=description,
                severity=severity,
                published_date=None,  # Will be parsed from dates
                references=[]  # Will be populated from references
            )
        
        except Exception as e:
            print(f"Error parsing CVE data: {e}")
            return None
    
    def _is_component_affected(self, component: SPDXPackage, vulnerability: Vulnerability) -> bool:
        """Check if component is affected by vulnerability"""
        # Simple version matching - can be enhanced with semantic versioning
        component_version = component.version_info or ""
        
        for affected_version in vulnerability.affected_versions:
            if component_version in affected_version:
                return True
        
        return False
```

---

## Implementation Checklist

### Week 1 Tasks:
- [ ] Create project directory structure
- [ ] Set up Python virtual environment
- [ ] Install backend dependencies
- [ ] Initialize React frontend project
- [ ] Install frontend dependencies
- [ ] Create configuration files
- [ ] Set up GitHub Actions workflow
- [ ] Configure pre-commit hooks

### Week 2 Tasks:
- [ ] Implement base package manager scanner
- [ ] Create NPM/Yarn scanner
- [ ] Create Python pip scanner
- [ ] Create Maven scanner
- [ ] Implement scanner registry
- [ ] Create SPDX data models
- [ ] Create CycloneDX data models
- [ ] Create vulnerability data models
- [ ] Implement CVE API client
- [ ] Create vulnerability scanner
- [ ] Write unit tests for all components
- [ ] Test integration between components

### Testing Strategy:
1. **Unit Tests**: Test each scanner individually
2. **Integration Tests**: Test scanner registry with multiple package managers
3. **End-to-End Tests**: Test complete SBOM generation workflow
4. **Performance Tests**: Test with large projects
5. **Security Tests**: Validate CVE API integration

### Next Steps After Week 2:
- Database integration (Week 3)
- API endpoints (Week 4)
- Frontend components (Week 9)
- Advanced features (Weeks 5-8)

This implementation plan provides a solid foundation for building the FDA-compliant SBOM generator with comprehensive package manager support and vulnerability scanning capabilities.


