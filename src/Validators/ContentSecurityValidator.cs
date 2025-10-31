using System;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace SeismicKnowledge.Api.Validators
{
    /// <summary>
    /// Validates content for security threats including SSRF, code injection, and malicious URLs.
    /// Implementation for User Stories STORY-001 and STORY-002.
    /// </summary>
    public static class ContentSecurityValidator
    {
        private static readonly string[] SuspiciousPatterns = new[]
        {
            // SSRF - AWS Metadata Endpoints
            "169.254.169.254",
            "fd00:ec2::254",
            "169.254.170.2", // ECS metadata
            
            // SSRF - GCP Metadata Endpoints
            "metadata.google.internal",
            "metadata/computeMetadata",
            
            // SSRF - Azure Metadata Endpoints
            "metadata.azure.com",
            
            // SSRF - Localhost/Loopback
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "[::1]",
            "::1",
            
            // SSRF - Private IP Ranges
            "10.0.0.",
            "192.168.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            
            // Dangerous Protocols
            "file://",
            "gopher://",
            "dict://",
            "ftp://localhost",
            
            // Code Injection - Python
            "import requests",
            "import urllib",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "__import__",
            "os.system",
            "os.popen",
            "eval(",
            "exec(",
            
            // Code Injection - PHP
            "<?php",
            "<?=",
            "exec(",
            "system(",
            "passthru(",
            "shell_exec(",
            "popen(",
            "proc_open(",
            
            // Code Injection - JSP/Java
            "<%@",
            "<jsp:",
            "<%",
            "%>",
            
            // Dangerous JavaScript
            "javascript:",
            "vbscript:",
            "data:text/html",
            "data:application/"
        };

        /// <summary>
        /// Validates content for security threats. Returns false if malicious patterns detected.
        /// </summary>
        /// <param name="content">Content to validate</param>
        /// <param name="userId">User ID for logging</param>
        /// <param name="companyId">Company ID for logging</param>
        /// <param name="logger">Logger instance</param>
        /// <returns>True if content is safe, false if malicious patterns detected</returns>
        public static bool IsContentSafe(string content, int userId, int companyId, ILogger logger)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return true; // Empty content is safe (will be caught by required validation)
            }

            // Case-insensitive search for performance
            var contentLower = content.ToLowerInvariant();

            foreach (var pattern in SuspiciousPatterns)
            {
                if (contentLower.Contains(pattern.ToLowerInvariant()))
                {
                    // Log security event
                    logger.LogWarning(
                        "SECURITY: Suspicious content detected. " +
                        "Pattern={Pattern}, UserId={UserId}, CompanyId={CompanyId}, " +
                        "Timestamp={Timestamp}, Endpoint=/api/content/save",
                        pattern,
                        userId,
                        companyId,
                        DateTime.UtcNow
                    );

                    // Return false to reject the request
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Validates a URL for security threats (used for attachment URLs).
        /// </summary>
        /// <param name="url">URL to validate</param>
        /// <param name="logger">Logger instance</param>
        /// <returns>True if URL is safe, false if malicious patterns detected</returns>
        public static bool IsUrlSafe(string url, ILogger logger)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return true;
            }

            var urlLower = url.ToLowerInvariant();

            // Check for dangerous patterns in URLs
            var urlPatterns = new[]
            {
                "169.254.169.254",
                "metadata.google.internal",
                "metadata.azure.com",
                "localhost",
                "127.0.0.1",
                "file://",
                "gopher://",
                "dict://",
                "javascript:",
                "vbscript:",
                "data:"
            };

            foreach (var pattern in urlPatterns)
            {
                if (urlLower.Contains(pattern))
                {
                    logger.LogWarning(
                        "SECURITY: Suspicious URL detected. Pattern={Pattern}, URL={Url}, Timestamp={Timestamp}",
                        pattern,
                        url.Substring(0, Math.Min(100, url.Length)), // Log first 100 chars only
                        DateTime.UtcNow
                    );
                    return false;
                }
            }

            // Additional check for private IP ranges
            try
            {
                var uri = new Uri(url);
                var host = uri.Host.ToLowerInvariant();

                if (host.StartsWith("10.") ||
                    host.StartsWith("192.168.") ||
                    host.StartsWith("172.16.") ||
                    host.StartsWith("172.17.") ||
                    host.StartsWith("172.18.") ||
                    host.StartsWith("172.19.") ||
                    host.StartsWith("172.20.") ||
                    host.StartsWith("172.21.") ||
                    host.StartsWith("172.22.") ||
                    host.StartsWith("172.23.") ||
                    host.StartsWith("172.24.") ||
                    host.StartsWith("172.25.") ||
                    host.StartsWith("172.26.") ||
                    host.StartsWith("172.27.") ||
                    host.StartsWith("172.28.") ||
                    host.StartsWith("172.29.") ||
                    host.StartsWith("172.30.") ||
                    host.StartsWith("172.31."))
                {
                    logger.LogWarning(
                        "SECURITY: Private IP in URL detected. Host={Host}, Timestamp={Timestamp}",
                        host,
                        DateTime.UtcNow
                    );
                    return false;
                }
            }
            catch (UriFormatException)
            {
                // If URL is malformed, let it through - will be caught by other validation
                return true;
            }

            return true;
        }

        /// <summary>
        /// Gets a safe error message to return to users (doesn't expose patterns).
        /// </summary>
        public static string GetSafeErrorMessage()
        {
            return "Content contains forbidden patterns";
        }
    }
}