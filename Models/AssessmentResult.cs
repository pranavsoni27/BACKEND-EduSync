using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EduSyncAPI.Models
{
    public class AssessmentResult
    {
        [Key]
        public Guid ResultId { get; set; }

        [Required]
        public Guid AssessmentId { get; set; }

        [ForeignKey("AssessmentId")]
        public Assessment Assessment { get; set; } = null!;

        [Required]
        public Guid UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; } = null!;

        [Required]
        public int Score { get; set; }

        [Required]
        public int MaxScore { get; set; }

        [Required]
        public DateTime SubmittedAt { get; set; }

        public List<QuestionResponse> Responses { get; set; } = new List<QuestionResponse>();
    }

    public class QuestionResponse
    {
        [Key]
        public Guid ResponseId { get; set; }

        [Required]
        public Guid ResultId { get; set; }

        [ForeignKey("ResultId")]
        public AssessmentResult Result { get; set; } = null!;

        [Required]
        public int QuestionIndex { get; set; }

        [Required]
        public int SelectedOptionIndex { get; set; }

        [Required]
        public bool IsCorrect { get; set; }

        [Required]
        public int MarksObtained { get; set; }
    }
} 