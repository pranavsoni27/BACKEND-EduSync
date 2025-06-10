using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using EduSyncAPI.Models;

namespace EduSyncAPI.DTOs.Assessments
{
    public class GetAssessmentDto
    {
        [JsonPropertyName("assessmentId")]
        public Guid AssessmentId { get; set; }

        [JsonPropertyName("courseId")]
        public Guid CourseId { get; set; }

        [JsonPropertyName("title")]
        public string Title { get; set; }

        [JsonPropertyName("questions")]
        public List<Question> Questions { get; set; }

        [JsonPropertyName("maxScore")]
        public int MaxScore { get; set; }

        [JsonPropertyName("duration")]
        public int Duration { get; set; }
    }
}
