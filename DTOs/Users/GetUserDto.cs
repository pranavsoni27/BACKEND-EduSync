using System;

namespace EduSyncAPI.DTOs.Users
{
    public class GetUserDto
    {
        public Guid UserId { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }  // "Student" or "Instructor"
    }
}
