using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.Models
{
    public class Course
    {
        [Key]
        public Guid CourseId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public Guid InstructorId { get; set; }
        public string MediaUrl { get; set; }
        public List<CourseContent>? Contents { get; set; }
        public List<Assessment>? Assessments { get; set; }
        public List<CourseEnrollment>? Enrollments { get; set; }
    }
}
