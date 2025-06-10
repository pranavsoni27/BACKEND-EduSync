using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EduSyncAPI.Models;

public partial class User
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid UserId { get; set; }

    [Required]
    [MaxLength(50)]
    public string Name { get; set; }

    [Required]
    [EmailAddress]
    [MaxLength(50)]
    public string Email { get; set; }

    [Required]
    [MaxLength(50)]
    public string Role { get; set; }

    [Required]
    [MaxLength(50)]
    public string PasswordHash { get; set; }
}
