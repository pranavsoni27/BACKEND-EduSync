using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.DTOs.Courses
{
    public class CreateContentDto
    {
        [Required]
        public string Title { get; set; }

        [Required]
        public string Description { get; set; }

        [Required]
        [Url]
        public string Url { get; set; }

        [Required]
        public string Type { get; set; }
    }
} 