using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using EduSyncAPI.Models;

namespace EduSyncAPI.DTOs.Assessments
{
    public class McqQuestionDto
    {
        [Required]
        [JsonPropertyName("text")]
        public string Text { get; set; }

        [Required]
        [JsonPropertyName("options")]
        public List<string> Options { get; set; }

        [Required]
        [JsonPropertyName("correctOptionIndex")]
        public int CorrectOptionIndex { get; set; }

        [Required]
        [JsonPropertyName("marks")]
        public int Marks { get; set; }
    }

    public class CreateAssessmentDto
    {
        [Required]
        public string Title { get; set; } = null!;
        
        [Required]
        public string Description { get; set; } = null!;
        
        [Required]
        public Guid CourseId { get; set; }
        
        [Required]
        public DateTime StartDate { get; set; }
        
        [Required]
        public DateTime EndDate { get; set; }
        
        [Required]
        public int DurationMinutes { get; set; }
        
        [Required]
        public int PassingScore { get; set; }
        
        [Required]
        public List<McqQuestionDto> Questions { get; set; } = new List<McqQuestionDto>();
    }
}
