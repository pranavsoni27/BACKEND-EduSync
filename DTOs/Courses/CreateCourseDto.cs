using System;
using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.DTOs.Courses
{
    public class CreateCourseDto
    {
        [Required]
        [MaxLength(50)]
        public string Title { get; set; }

        [Required]
        [MaxLength(50)]
        public string Description { get; set; }

        [Required]
        public Guid InstructorId { get; set; }

        [Required]
        [MaxLength(50)]
        public string MediaUrl { get; set; }
    }
}
