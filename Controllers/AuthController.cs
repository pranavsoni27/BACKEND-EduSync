using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EduSyncAPI.Data;
using EduSyncAPI.Models;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace EduSyncAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<AuthController> _logger;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, ILogger<AuthController> logger, IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
        }

        private string HashPassword(string password)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                    return Convert.ToBase64String(hashedBytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password");
                throw new Exception("Error processing password");
            }
        }

        private string GenerateJwtToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpiryInMinutes"])),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            try
            {
                _logger.LogInformation("Register request received from origin: {Origin}", Request.Headers["Origin"]);
                _logger.LogInformation("Register request headers: {Headers}", 
                    string.Join(", ", Request.Headers.Select(h => $"{h.Key}: {h.Value}")));

                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                    _logger.LogWarning("Invalid registration data: {Errors}", string.Join(", ", errors));
                    return BadRequest(new { message = "Invalid input data", errors });
                }

                if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                {
                    _logger.LogWarning("Registration failed: User already exists - {Email}", model.Email);
                    return BadRequest(new { message = "User already exists" });
                }

                var user = new User
                {
                    UserId = Guid.NewGuid(),
                    Email = model.Email,
                    PasswordHash = HashPassword(model.Password),
                    Role = model.Role,
                    Name = model.Email.Contains("@") ? model.Email.Split('@')[0] : model.Email
                };

                _logger.LogInformation("Creating new user with data: {UserId}, {Email}, {Role}", 
                    user.UserId, user.Email, user.Role);

                try 
                {
                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("User saved successfully to database");
                }
                catch (DbUpdateException dbEx)
                {
                    _logger.LogError(dbEx, "Database error while saving user: {Message}", dbEx.Message);
                    if (dbEx.InnerException != null)
                    {
                        _logger.LogError("Inner exception: {Message}", dbEx.InnerException.Message);
                    }
                    return StatusCode(500, new { message = "Database error while saving user", error = dbEx.Message });
                }

                var token = GenerateJwtToken(user);

                _logger.LogInformation("User registered successfully: {Email}", model.Email);

                return Ok(new { 
                    token = token, 
                    id = user.UserId,
                    email = user.Email,
                    role = user.Role
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for user: {Email}", model.Email);
                return StatusCode(500, new { message = "An error occurred during registration", error = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                _logger.LogInformation("Login request received from origin: {Origin}", Request.Headers["Origin"]);
                _logger.LogInformation("Login request headers: {Headers}", 
                    string.Join(", ", Request.Headers.Select(h => $"{h.Key}: {h.Value}")));

                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                    _logger.LogWarning("Invalid login data: {Errors}", string.Join(", ", errors));
                    return BadRequest(new { message = "Invalid input data", errors });
                }

                var user = await _context.Users.FirstOrDefaultAsync(u =>
                    u.Email == model.Email &&
                    u.PasswordHash == HashPassword(model.Password) &&
                    u.Role == model.Role);

                if (user == null)
                {
                    _logger.LogWarning("Login failed: Invalid credentials for user: {Email}", model.Email);
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                var token = GenerateJwtToken(user);

                _logger.LogInformation("User logged in successfully: {Email}", model.Email);

                return Ok(new { 
                    token = token, 
                    id = user.UserId,
                    email = user.Email,
                    role = user.Role
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for user: {Email}", model.Email);
                return StatusCode(500, new { message = "An error occurred during login", error = ex.Message });
            }
        }
    }

    // Models can be declared here OR in separate files in a Models folder
    public class UserModel
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
        public string Token { get; set; }
    }

    public class RegisterModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Role is required")]
        public string Role { get; set; }
    }

    public class LoginModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Role is required")]
        public string Role { get; set; }
    }
}
