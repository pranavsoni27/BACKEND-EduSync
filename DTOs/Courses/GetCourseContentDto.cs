using System;

namespace EduSyncAPI.DTOs.Courses
{
    public class GetCourseContentDto
    {
        public Guid ContentId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        public string Url { get; set; }
        public int Order { get; set; }
    }
} 