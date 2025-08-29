"""Encrypted storage system for sensitive analysis results."""

import os
import json
import sqlite3
import hashlib
import logging
from typing import Dict, List, Optional, Any, Union, BinaryIO
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import base64
import gzip
from abc import ABC, abstractmethod

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


logger = logging.getLogger(__name__)


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes_256_gcm"
    FERNET = "fernet"
    RSA_OAEP = "rsa_oaep"
    CHACHA20_POLY1305 = "chacha20_poly1305"


class CompressionType(Enum):
    """Supported compression types."""
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"


@dataclass
class EncryptionConfig:
    """Configuration for encryption settings."""
    
    # Encryption settings
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.FERNET
    key_derivation_iterations: int = 100000
    
    # Key management
    key_rotation_days: int = 90
    auto_rotate_keys: bool = True
    
    # Compression
    compression: CompressionType = CompressionType.GZIP
    compression_level: int = 6
    
    # Security settings
    require_authentication: bool = True
    audit_access: bool = True
    
    # Performance settings
    chunk_size: int = 8192
    cache_decrypted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'algorithm': self.algorithm.value,
            'key_derivation_iterations': self.key_derivation_iterations,
            'key_rotation_days': self.key_rotation_days,
            'auto_rotate_keys': self.auto_rotate_keys,
            'compression': self.compression.value,
            'compression_level': self.compression_level,
            'require_authentication': self.require_authentication,
            'audit_access': self.audit_access,
            'chunk_size': self.chunk_size,
            'cache_decrypted': self.cache_decrypted
        }


@dataclass
class EncryptedData:
    """Represents encrypted data with metadata."""
    
    data_id: str
    encrypted_content: bytes
    
    # Encryption metadata
    algorithm: EncryptionAlgorithm
    key_id: str
    iv: Optional[bytes] = None
    
    # Content metadata
    original_size: int = 0
    compressed_size: int = 0
    compression_type: CompressionType = CompressionType.NONE
    content_type: str = "application/octet-stream"
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: Optional[datetime] = None
    
    # Integrity
    checksum: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding encrypted content)."""
        return {
            'data_id': self.data_id,
            'algorithm': self.algorithm.value,
            'key_id': self.key_id,
            'original_size': self.original_size,
            'compressed_size': self.compressed_size,
            'compression_type': self.compression_type.value,
            'content_type': self.content_type,
            'created_at': self.created_at.isoformat(),
            'accessed_at': self.accessed_at.isoformat() if self.accessed_at else None,
            'checksum': self.checksum,
            'has_iv': self.iv is not None
        }


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def store(self, data_id: str, encrypted_data: EncryptedData) -> bool:
        """Store encrypted data."""
        pass
    
    @abstractmethod
    def retrieve(self, data_id: str) -> Optional[EncryptedData]:
        """Retrieve encrypted data."""
        pass
    
    @abstractmethod
    def delete(self, data_id: str) -> bool:
        """Delete encrypted data."""
        pass
    
    @abstractmethod
    def list_data_ids(self) -> List[str]:
        """List all data IDs."""
        pass
    
    @abstractmethod
    def exists(self, data_id: str) -> bool:
        """Check if data exists."""
        pass


class FileSystemBackend(StorageBackend):
    """File system storage backend."""
    
    def __init__(self, storage_path: str):
        """Initialize file system backend."""
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def store(self, data_id: str, encrypted_data: EncryptedData) -> bool:
        """Store encrypted data to file system."""
        try:
            # Create data directory
            data_dir = self.storage_path / data_id
            data_dir.mkdir(exist_ok=True)
            
            # Store encrypted content
            content_path = data_dir / "content.enc"
            with open(content_path, 'wb') as f:
                f.write(encrypted_data.encrypted_content)
            
            # Store metadata
            metadata_path = data_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(encrypted_data.to_dict(), f, indent=2)
            
            # Store IV if present
            if encrypted_data.iv:
                iv_path = data_dir / "iv.bin"
                with open(iv_path, 'wb') as f:
                    f.write(encrypted_data.iv)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing data {data_id}: {e}")
            return False
    
    def retrieve(self, data_id: str) -> Optional[EncryptedData]:
        """Retrieve encrypted data from file system."""
        try:
            data_dir = self.storage_path / data_id
            
            if not data_dir.exists():
                return None
            
            # Load metadata
            metadata_path = data_dir / "metadata.json"
            if not metadata_path.exists():
                return None
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Load encrypted content
            content_path = data_dir / "content.enc"
            if not content_path.exists():
                return None
            
            with open(content_path, 'rb') as f:
                encrypted_content = f.read()
            
            # Load IV if present
            iv = None
            iv_path = data_dir / "iv.bin"
            if iv_path.exists():
                with open(iv_path, 'rb') as f:
                    iv = f.read()
            
            # Reconstruct EncryptedData object
            encrypted_data = EncryptedData(
                data_id=data_id,
                encrypted_content=encrypted_content,
                algorithm=EncryptionAlgorithm(metadata['algorithm']),
                key_id=metadata['key_id'],
                iv=iv,
                original_size=metadata['original_size'],
                compressed_size=metadata['compressed_size'],
                compression_type=CompressionType(metadata['compression_type']),
                content_type=metadata['content_type'],
                created_at=datetime.fromisoformat(metadata['created_at']),
                accessed_at=datetime.fromisoformat(metadata['accessed_at']) if metadata['accessed_at'] else None,
                checksum=metadata['checksum']
            )
            
            # Update access time
            encrypted_data.accessed_at = datetime.now()
            
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Error retrieving data {data_id}: {e}")
            return None
    
    def delete(self, data_id: str) -> bool:
        """Delete encrypted data from file system."""
        try:
            data_dir = self.storage_path / data_id
            
            if data_dir.exists():
                # Remove all files in directory
                for file_path in data_dir.iterdir():
                    file_path.unlink()
                
                # Remove directory
                data_dir.rmdir()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting data {data_id}: {e}")
            return False
    
    def list_data_ids(self) -> List[str]:
        """List all data IDs."""
        try:
            return [d.name for d in self.storage_path.iterdir() if d.is_dir()]
        except Exception as e:
            self.logger.error(f"Error listing data IDs: {e}")
            return []
    
    def exists(self, data_id: str) -> bool:
        """Check if data exists."""
        data_dir = self.storage_path / data_id
        return data_dir.exists() and (data_dir / "content.enc").exists()


class DatabaseBackend(StorageBackend):
    """SQLite database storage backend."""
    
    def __init__(self, db_path: str):
        """Initialize database backend."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS encrypted_data (
                        data_id TEXT PRIMARY KEY,
                        encrypted_content BLOB NOT NULL,
                        algorithm TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        iv BLOB,
                        original_size INTEGER NOT NULL,
                        compressed_size INTEGER NOT NULL,
                        compression_type TEXT NOT NULL,
                        content_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        accessed_at TEXT,
                        checksum TEXT
                    )
                ''')
                
                # Create index for faster lookups
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_created_at 
                    ON encrypted_data(created_at)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def store(self, data_id: str, encrypted_data: EncryptedData) -> bool:
        """Store encrypted data to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO encrypted_data (
                        data_id, encrypted_content, algorithm, key_id, iv,
                        original_size, compressed_size, compression_type,
                        content_type, created_at, accessed_at, checksum
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data_id,
                    encrypted_data.encrypted_content,
                    encrypted_data.algorithm.value,
                    encrypted_data.key_id,
                    encrypted_data.iv,
                    encrypted_data.original_size,
                    encrypted_data.compressed_size,
                    encrypted_data.compression_type.value,
                    encrypted_data.content_type,
                    encrypted_data.created_at.isoformat(),
                    encrypted_data.accessed_at.isoformat() if encrypted_data.accessed_at else None,
                    encrypted_data.checksum
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing data {data_id}: {e}")
            return False
    
    def retrieve(self, data_id: str) -> Optional[EncryptedData]:
        """Retrieve encrypted data from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM encrypted_data WHERE data_id = ?
                ''', (data_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Reconstruct EncryptedData object
                encrypted_data = EncryptedData(
                    data_id=row[0],
                    encrypted_content=row[1],
                    algorithm=EncryptionAlgorithm(row[2]),
                    key_id=row[3],
                    iv=row[4],
                    original_size=row[5],
                    compressed_size=row[6],
                    compression_type=CompressionType(row[7]),
                    content_type=row[8],
                    created_at=datetime.fromisoformat(row[9]),
                    accessed_at=datetime.fromisoformat(row[10]) if row[10] else None,
                    checksum=row[11]
                )
                
                # Update access time
                encrypted_data.accessed_at = datetime.now()
                
                # Update access time in database
                conn.execute('''
                    UPDATE encrypted_data SET accessed_at = ? WHERE data_id = ?
                ''', (encrypted_data.accessed_at.isoformat(), data_id))
                
                conn.commit()
                
                return encrypted_data
                
        except Exception as e:
            self.logger.error(f"Error retrieving data {data_id}: {e}")
            return None
    
    def delete(self, data_id: str) -> bool:
        """Delete encrypted data from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM encrypted_data WHERE data_id = ?', (data_id,))
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error deleting data {data_id}: {e}")
            return False
    
    def list_data_ids(self) -> List[str]:
        """List all data IDs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT data_id FROM encrypted_data ORDER BY created_at')
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error listing data IDs: {e}")
            return []
    
    def exists(self, data_id: str) -> bool:
        """Check if data exists."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT 1 FROM encrypted_data WHERE data_id = ?', (data_id,))
                return cursor.fetchone() is not None
                
        except Exception as e:
            self.logger.error(f"Error checking existence of {data_id}: {e}")
            return False


class CloudStorageBackend(StorageBackend):
    """Cloud storage backend (mock implementation)."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize cloud storage backend."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # In a real implementation, this would initialize cloud storage clients
        # For now, we'll use a simple in-memory storage for demonstration
        self._storage = {}
    
    def store(self, data_id: str, encrypted_data: EncryptedData) -> bool:
        """Store encrypted data to cloud storage."""
        try:
            # In a real implementation, this would upload to cloud storage
            self._storage[data_id] = encrypted_data
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing data {data_id}: {e}")
            return False
    
    def retrieve(self, data_id: str) -> Optional[EncryptedData]:
        """Retrieve encrypted data from cloud storage."""
        try:
            encrypted_data = self._storage.get(data_id)
            if encrypted_data:
                encrypted_data.accessed_at = datetime.now()
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Error retrieving data {data_id}: {e}")
            return None
    
    def delete(self, data_id: str) -> bool:
        """Delete encrypted data from cloud storage."""
        try:
            if data_id in self._storage:
                del self._storage[data_id]
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting data {data_id}: {e}")
            return False
    
    def list_data_ids(self) -> List[str]:
        """List all data IDs."""
        return list(self._storage.keys())
    
    def exists(self, data_id: str) -> bool:
        """Check if data exists."""
        return data_id in self._storage


class EncryptedStorage:
    """Main encrypted storage system."""
    
    def __init__(self, 
                 backend: StorageBackend,
                 config: Optional[EncryptionConfig] = None,
                 master_key: Optional[bytes] = None):
        """Initialize encrypted storage."""
        
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library is required for encrypted storage")
        
        self.backend = backend
        self.config = config or EncryptionConfig()
        self.logger = logging.getLogger(__name__)
        
        # Key management
        self.master_key = master_key or self._generate_master_key()
        self.encryption_keys = {}
        self.current_key_id = self._generate_key_id()
        
        # Initialize encryption key
        self._initialize_encryption_key()
    
    def _generate_master_key(self) -> bytes:
        """Generate master key for key derivation."""
        return os.urandom(32)  # 256-bit key
    
    def _generate_key_id(self) -> str:
        """Generate unique key ID."""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    
    def _initialize_encryption_key(self):
        """Initialize encryption key for current key ID."""
        
        if self.config.algorithm == EncryptionAlgorithm.FERNET:
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.current_key_id.encode(),
                iterations=self.config.key_derivation_iterations,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
            self.encryption_keys[self.current_key_id] = Fernet(key)
        
        else:
            # For other algorithms, implement key derivation as needed
            self.encryption_keys[self.current_key_id] = self.master_key
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data according to configuration."""
        
        if self.config.compression == CompressionType.GZIP:
            return gzip.compress(data, compresslevel=self.config.compression_level)
        elif self.config.compression == CompressionType.ZLIB:
            import zlib
            return zlib.compress(data, level=self.config.compression_level)
        else:
            return data
    
    def _decompress_data(self, data: bytes, compression_type: CompressionType) -> bytes:
        """Decompress data."""
        
        if compression_type == CompressionType.GZIP:
            return gzip.decompress(data)
        elif compression_type == CompressionType.ZLIB:
            import zlib
            return zlib.decompress(data)
        else:
            return data
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate checksum for data integrity."""
        return hashlib.sha256(data).hexdigest()
    
    def store(self, 
              data_id: str,
              data: Union[str, bytes, Dict, List],
              content_type: str = "application/json") -> bool:
        """Store data with encryption."""
        
        try:
            # Convert data to bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, (dict, list)):
                data_bytes = json.dumps(data).encode('utf-8')
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                data_bytes = str(data).encode('utf-8')
            
            original_size = len(data_bytes)
            
            # Compress data
            compressed_data = self._compress_data(data_bytes)
            compressed_size = len(compressed_data)
            
            # Calculate checksum
            checksum = self._calculate_checksum(data_bytes)
            
            # Encrypt data
            if self.config.algorithm == EncryptionAlgorithm.FERNET:
                fernet = self.encryption_keys[self.current_key_id]
                encrypted_content = fernet.encrypt(compressed_data)
                iv = None
            else:
                # For other algorithms, implement encryption as needed
                encrypted_content = compressed_data
                iv = None
            
            # Create encrypted data object
            encrypted_data = EncryptedData(
                data_id=data_id,
                encrypted_content=encrypted_content,
                algorithm=self.config.algorithm,
                key_id=self.current_key_id,
                iv=iv,
                original_size=original_size,
                compressed_size=compressed_size,
                compression_type=self.config.compression,
                content_type=content_type,
                checksum=checksum
            )
            
            # Store using backend
            success = self.backend.store(data_id, encrypted_data)
            
            if success and self.config.audit_access:
                self.logger.info(f"Stored encrypted data: {data_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error storing encrypted data {data_id}: {e}")
            return False
    
    def retrieve(self, data_id: str) -> Optional[Any]:
        """Retrieve and decrypt data."""
        
        try:
            # Retrieve encrypted data
            encrypted_data = self.backend.retrieve(data_id)
            if not encrypted_data:
                return None
            
            # Get decryption key
            if encrypted_data.key_id not in self.encryption_keys:
                self.logger.error(f"Encryption key not found for key ID: {encrypted_data.key_id}")
                return None
            
            # Decrypt data
            if encrypted_data.algorithm == EncryptionAlgorithm.FERNET:
                fernet = self.encryption_keys[encrypted_data.key_id]
                decrypted_data = fernet.decrypt(encrypted_data.encrypted_content)
            else:
                # For other algorithms, implement decryption as needed
                decrypted_data = encrypted_data.encrypted_content
            
            # Decompress data
            decompressed_data = self._decompress_data(decrypted_data, encrypted_data.compression_type)
            
            # Verify checksum
            if encrypted_data.checksum:
                calculated_checksum = self._calculate_checksum(decompressed_data)
                if calculated_checksum != encrypted_data.checksum:
                    self.logger.error(f"Checksum mismatch for data {data_id}")
                    return None
            
            # Convert back to appropriate type based on content type
            if encrypted_data.content_type == "application/json":
                try:
                    return json.loads(decompressed_data.decode('utf-8'))
                except json.JSONDecodeError:
                    return decompressed_data.decode('utf-8')
            elif encrypted_data.content_type.startswith("text/"):
                return decompressed_data.decode('utf-8')
            else:
                return decompressed_data
            
        except Exception as e:
            self.logger.error(f"Error retrieving encrypted data {data_id}: {e}")
            return None
    
    def delete(self, data_id: str) -> bool:
        """Delete encrypted data."""
        
        try:
            success = self.backend.delete(data_id)
            
            if success and self.config.audit_access:
                self.logger.info(f"Deleted encrypted data: {data_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting encrypted data {data_id}: {e}")
            return False
    
    def list_data_ids(self) -> List[str]:
        """List all stored data IDs."""
        return self.backend.list_data_ids()
    
    def exists(self, data_id: str) -> bool:
        """Check if data exists."""
        return self.backend.exists(data_id)
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        
        data_ids = self.list_data_ids()
        total_count = len(data_ids)
        
        if total_count == 0:
            return {
                'total_items': 0,
                'total_size': 0,
                'compression_ratio': 0.0,
                'oldest_item': None,
                'newest_item': None
            }
        
        total_original_size = 0
        total_compressed_size = 0
        oldest_date = None
        newest_date = None
        
        for data_id in data_ids:
            encrypted_data = self.backend.retrieve(data_id)
            if encrypted_data:
                total_original_size += encrypted_data.original_size
                total_compressed_size += encrypted_data.compressed_size
                
                if oldest_date is None or encrypted_data.created_at < oldest_date:
                    oldest_date = encrypted_data.created_at
                
                if newest_date is None or encrypted_data.created_at > newest_date:
                    newest_date = encrypted_data.created_at
        
        compression_ratio = (total_original_size - total_compressed_size) / total_original_size if total_original_size > 0 else 0.0
        
        return {
            'total_items': total_count,
            'total_original_size': total_original_size,
            'total_compressed_size': total_compressed_size,
            'compression_ratio': compression_ratio,
            'oldest_item': oldest_date.isoformat() if oldest_date else None,
            'newest_item': newest_date.isoformat() if newest_date else None
        }
    
    def rotate_keys(self) -> bool:
        """Rotate encryption keys."""
        
        try:
            # Generate new key ID
            new_key_id = self._generate_key_id()
            
            # Initialize new encryption key
            old_key_id = self.current_key_id
            self.current_key_id = new_key_id
            self._initialize_encryption_key()
            
            self.logger.info(f"Rotated encryption keys: {old_key_id} -> {new_key_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error rotating keys: {e}")
            return False


# Utility functions

def create_file_storage(storage_path: str, 
                       config: Optional[EncryptionConfig] = None) -> EncryptedStorage:
    """Create encrypted storage with file system backend."""
    
    backend = FileSystemBackend(storage_path)
    return EncryptedStorage(backend, config)


def create_database_storage(db_path: str,
                          config: Optional[EncryptionConfig] = None) -> EncryptedStorage:
    """Create encrypted storage with database backend."""
    
    backend = DatabaseBackend(db_path)
    return EncryptedStorage(backend, config)


def create_secure_config() -> EncryptionConfig:
    """Create secure encryption configuration."""
    
    return EncryptionConfig(
        algorithm=EncryptionAlgorithm.FERNET,
        key_derivation_iterations=200000,
        key_rotation_days=30,
        auto_rotate_keys=True,
        compression=CompressionType.GZIP,
        compression_level=9,
        require_authentication=True,
        audit_access=True,
        cache_decrypted=False
    )