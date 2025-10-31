using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace SeismicKnowledge.Api.Models
{
    /// <summary>
    /// Standardized error response model for all API errors.
    /// Implements STORY-003 error handling requirements.
    /// Created: 2025-10-31 06:10:27 UTC
    /// Author: SampathKumarbn
    /// </summary>
    public class ErrorResponse
    {
        [JsonProperty("error")]
        public string Error { get; set; }

        [JsonProperty("detail")]
        public string Detail { get; set; }

        [JsonProperty("details")]
        public List<string> Details { get; set; }

        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("correlationId")]
        public string CorrelationId { get; set; }

        [JsonProperty("path")]
        public string Path { get; set; }

        [JsonProperty("lineNumber")]
        public int? LineNumber { get; set; }

        [JsonProperty("bytePositionInLine")]
        public int? BytePositionInLine { get; set; }
    }
}