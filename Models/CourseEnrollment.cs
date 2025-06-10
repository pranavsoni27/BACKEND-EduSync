using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EduSyncAPI.Models
{
    public class CourseEnrollment
    {
        [Key]
        public Guid EnrollmentId { get; set; }
        public Guid CourseId { get; set; }
        public Guid UserId { get; set; }
        public DateTime EnrollmentDate { get; set; }

        // Navigation properties
        public Course? Course { get; set; }
        public User? User { get; set; }
    }
} 