using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace EduSyncAPI.DTOs.Assessments
{
    public class UpdateAssessmentDto
    {
        [Required]
        [JsonPropertyName("courseId")]
        public Guid CourseId { get; set; }

        [Required]
        [MaxLength(50)]
        [JsonPropertyName("title")]
        public string Title { get; set; }

        [Required]
        [JsonPropertyName("questions")]
        public List<McqQuestionDto> Questions { get; set; }
    }
}
