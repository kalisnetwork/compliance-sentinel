"""Multi-language analysis coordinator."""

import asyncio
from typing import List, Dict, Optional, Set
from pathlib import Path
import logging

from compliance_sentinel.core.interfaces import SecurityIssue
from compliance_sentinel.core.interfaces import AnalysisResult
from compliance_sentinel.analyzers.languages import (
    LanguageAnalyzer,
    LanguageDetector,
    LanguageAnalyzerRegistry,
    get_language_analyzer_registry,
    ProgrammingLanguage,
    JavaScriptAnalyzer,
    JavaAnalyzer,
    CSharpAnalyzer,
    GoAnalyzer,
    RustAnalyzer,
    PHPAnalyzer
)
from compliance_sentinel.analyzers.languages.javascript import TypeScriptAnalyzer


logger = logging.getLogger(__name__)


class MultiLanguageCoordinator:
    """Coordinates security analysis across multiple programming languages."""
    
    def __init__(self):
        """Initialize multi-language coordinator."""
        self.registry = get_language_analyzer_registry()
        self._initialize_analyzers()
        self.logger = logging.getLogger(__name__)
    
    def _initialize_analyzers(self) -> None:
        """Initialize and register all language analyzers."""
        analyzers = [
            JavaScriptAnalyzer(),
            TypeScriptAnalyzer(),
            JavaAnalyzer(),
            CSharpAnalyzer(),
            GoAnalyzer(),
            RustAnalyzer(),
            PHPAnalyzer(),
        ]
        
        for analyzer in analyzers:
            self.registry.register_analyzer(analyzer)
        
        self.logger.info(f"Initialized {len(analyzers)} language analyzers")
    
    async def analyze_files(self, file_paths: List[str]) -> List[AnalysisResult]:
        """
        Analyze multiple files using appropriate language analyzers.
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        
        # Group files by language for efficient processing
        files_by_language = self._group_files_by_language(file_paths)
        
        # Process each language group
        for language, files in files_by_language.items():
            analyzer = self.registry.get_analyzer(language)
            if analyzer:
                language_results = await self._analyze_language_files(analyzer, files)
                results.extend(language_results)
            else:
                self.logger.warning(f"No analyzer available for language: {language.value}")
        
        return results
    
    def _group_files_by_language(self, file_paths: List[str]) -> Dict[ProgrammingLanguage, List[str]]:
        """Group files by detected programming language."""
        files_by_language = {}
        
        for file_path in file_paths:
            try:
                # Read file content for better language detection
                content = None
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except (UnicodeDecodeError, IOError):
                    # Skip binary files or files we can't read
                    continue
                
                language = LanguageDetector.detect_language(file_path, content)
                
                if language not in files_by_language:
                    files_by_language[language] = []
                
                files_by_language[language].append(file_path)
                
            except Exception as e:
                self.logger.warning(f"Failed to process file {file_path}: {e}")
        
        return files_by_language
    
    async def _analyze_language_files(
        self, 
        analyzer: LanguageAnalyzer, 
        file_paths: List[str]
    ) -> List[AnalysisResult]:
        """Analyze files for a specific language."""
        results = []
        
        for file_path in file_paths:
            try:
                result = await self._analyze_single_file(analyzer, file_path)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path} with {analyzer.language.value} analyzer: {e}")
        
        return results
    
    async def _analyze_single_file(self, analyzer: LanguageAnalyzer, file_path: str) -> Optional[AnalysisResult]:
        """Analyze a single file with the given analyzer."""
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Analyze file
            issues = analyzer.analyze_file(file_path, content)
            
            # Create analysis result
            from datetime import datetime
            result = AnalysisResult(
                file_path=file_path,
                timestamp=datetime.now(),
                issues=issues,
                vulnerabilities=[]  # Language analyzers focus on code issues, not dependency vulnerabilities
            )
            
            self.logger.debug(f"Analyzed {file_path} with {analyzer.language.value}: {len(issues)} issues found")
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return None
    
    def get_supported_languages(self) -> List[ProgrammingLanguage]:
        """Get list of supported programming languages."""
        return self.registry.get_supported_languages()
    
    def get_supported_extensions(self) -> Set[str]:
        """Get all supported file extensions."""
        return LanguageDetector.get_supported_extensions()
    
    def can_analyze_file(self, file_path: str) -> bool:
        """Check if a file can be analyzed by any language analyzer."""
        language = LanguageDetector.detect_language(file_path)
        return self.registry.get_analyzer(language) is not None
    
    def get_analyzer_for_file(self, file_path: str) -> Optional[LanguageAnalyzer]:
        """Get the appropriate analyzer for a file."""
        return self.registry.get_analyzer_for_file(file_path)
    
    def get_language_statistics(self, file_paths: List[str]) -> Dict[str, int]:
        """Get statistics about language distribution in files."""
        stats = {}
        
        for file_path in file_paths:
            try:
                language = LanguageDetector.detect_language(file_path)
                language_name = language.value
                stats[language_name] = stats.get(language_name, 0) + 1
            except Exception:
                stats['unknown'] = stats.get('unknown', 0) + 1
        
        return stats
    
    async def analyze_project_directory(self, directory_path: str, recursive: bool = True) -> List[AnalysisResult]:
        """
        Analyze all supported files in a directory.
        
        Args:
            directory_path: Path to directory to analyze
            recursive: Whether to analyze subdirectories recursively
            
        Returns:
            List of analysis results
        """
        file_paths = []
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory does not exist: {directory_path}")
        
        # Find all supported files
        supported_extensions = self.get_supported_extensions()
        
        if recursive:
            for ext in supported_extensions:
                pattern = f"**/*{ext}"
                file_paths.extend([str(p) for p in directory.glob(pattern)])
        else:
            for ext in supported_extensions:
                pattern = f"*{ext}"
                file_paths.extend([str(p) for p in directory.glob(pattern)])
        
        self.logger.info(f"Found {len(file_paths)} files to analyze in {directory_path}")
        
        return await self.analyze_files(file_paths)


# Global coordinator instance
_global_coordinator: Optional[MultiLanguageCoordinator] = None


def get_multi_language_coordinator() -> MultiLanguageCoordinator:
    """Get global multi-language coordinator instance."""
    global _global_coordinator
    if _global_coordinator is None:
        _global_coordinator = MultiLanguageCoordinator()
    return _global_coordinator


def reset_multi_language_coordinator() -> None:
    """Reset global coordinator (for testing)."""
    global _global_coordinator
    _global_coordinator = None