using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;

namespace EduSyncAPI.Models;

public class Assessment
{
    [Key]
    public Guid AssessmentId { get; set; }

    [Required]
    public string Title { get; set; } = string.Empty;

    [Required]
    public int Duration { get; set; } // Duration in minutes

    [Required]
    public List<Question> Questions { get; set; } = new List<Question>();

    [Required]
    public Guid CourseId { get; set; }

    [ForeignKey("CourseId")]
    public Course Course { get; set; } = null!;

    public int MaxScore { get; set; }
}

public class Question
{
    [Required]
    public string Text { get; set; } = string.Empty;

    [Required]
    public List<string> Options { get; set; } = new List<string>();

    [Required]
    [Range(0, 5)]
    public int CorrectOptionIndex { get; set; }

    [Required]
    [Range(1, 10)]
    public int Marks { get; set; }
}
