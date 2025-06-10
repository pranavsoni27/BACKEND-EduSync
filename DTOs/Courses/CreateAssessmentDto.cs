using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.DTOs.Courses
{
    public class CreateAssessmentDto
    {
        [Required]
        public string Title { get; set; }

        [Required]
        [Range(1, 180)] // Duration in minutes, max 3 hours
        public int Duration { get; set; }

        [Required]
        [MinLength(1)]
        public List<CreateQuestionDto> Questions { get; set; }
    }

    public class CreateQuestionDto
    {
        [Required]
        public string Text { get; set; }

        [Required]
        [MinLength(2)]
        [MaxLength(6)]
        public List<string> Options { get; set; }

        [Required]
        [Range(0, 5)] // Assuming max 6 options
        public int CorrectOptionIndex { get; set; }

        [Required]
        [Range(1, 10)] // Max 10 marks per question
        public int Marks { get; set; }
    }
} 