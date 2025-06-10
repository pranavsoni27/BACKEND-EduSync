using System;
using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.Models
{
    public class CourseContent
    {
        [Key]
        public Guid ContentId { get; set; }
        public Guid CourseId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Url { get; set; }
        public string Type { get; set; } // 'document', 'video', etc.
        public int Order { get; set; }
        public DateTime CreatedAt { get; set; }

        // Navigation property
        public Course? Course { get; set; }
    }
}