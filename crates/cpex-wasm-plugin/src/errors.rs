use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum PluginError {
    FilePermissionDenied { path: String, reason: String },
    HttpPermissionDenied { url: String, reason: String },
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::FilePermissionDenied { path, reason } => {
                write!(f, "File permission denied for '{}': {}", path, reason)
            }
            PluginError::HttpPermissionDenied { url, reason } => {
                write!(f, "HTTP permission denied for '{}': {}", url, reason)
            }
        }
    }
}

impl PluginError {
    pub fn file_denied(path: impl Into<String>, reason: impl Into<String>) -> Self {
        PluginError::FilePermissionDenied {
            path: path.into(),
            reason: reason.into(),
        }
    }

    pub fn http_denied(url: impl Into<String>, reason: impl Into<String>) -> Self {
        PluginError::HttpPermissionDenied {
            url: url.into(),
            reason: reason.into(),
        }
    }
}
