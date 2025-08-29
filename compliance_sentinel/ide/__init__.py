"""IDE integration and user experience components."""

from .feedback_formatter import (
    IDEFeedbackFormatter, IDEType, FeedbackType, 
    IDEDiagnostic, IDEQuickFix, IDECodeAction, IDEHoverInfo, IDEFeedback
)
from .code_highlighter import (
    CodeHighlighter, HighlightType, HighlightStyle,
    CodeRange, CodeHighlight, FileHighlights
)
from .contextual_help import (
    ContextualHelpProvider, HelpContent, InteractiveExample, QuickReference
)
from .progress_indicators import (
    ProgressTracker, ProgressManager, AnalysisProgressTracker,
    ProgressType, ProgressState, ProgressInfo, ProgressStep,
    get_global_progress_manager, create_analysis_progress_tracker,
    IDEProgressFormatter
)

__all__ = [
    # Feedback formatting
    "IDEFeedbackFormatter",
    "IDEType", 
    "FeedbackType",
    "IDEDiagnostic",
    "IDEQuickFix", 
    "IDECodeAction",
    "IDEHoverInfo",
    "IDEFeedback",
    
    # Code highlighting
    "CodeHighlighter",
    "HighlightType",
    "HighlightStyle", 
    "CodeRange",
    "CodeHighlight",
    "FileHighlights",
    
    # Contextual help
    "ContextualHelpProvider",
    "HelpContent",
    "InteractiveExample",
    "QuickReference",
    
    # Progress indicators
    "ProgressTracker",
    "ProgressManager",
    "AnalysisProgressTracker",
    "ProgressType",
    "ProgressState", 
    "ProgressInfo",
    "ProgressStep",
    "get_global_progress_manager",
    "create_analysis_progress_tracker",
    "IDEProgressFormatter"
]