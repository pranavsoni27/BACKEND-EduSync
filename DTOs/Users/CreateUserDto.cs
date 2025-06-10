using System;
using System.ComponentModel.DataAnnotations;

namespace EduSyncAPI.DTOs.Users
{
    public class CreateUserDto
    {
        [Required]
        [MaxLength(50)]
        public string Name { get; set; }

        [Required]
        [EmailAddress]
        [MaxLength(50)]
        public string Email { get; set; }

        [Required]
        [MaxLength(50)]
        public string PasswordHash { get; set; }

        [Required]
        [MaxLength(50)]
        public string Role { get; set; }  // "Student" or "Instructor"
    }
}
