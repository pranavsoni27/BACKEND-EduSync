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
using EduSyncAPI.DTOs.Users;

namespace EduSyncAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            AppDbContext context,
            IConfiguration configuration,
            ILogger<AuthController> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        private string HashPassword(string password)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                    // Use a shorter hash format to fit within 256 characters
                    return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password");
                throw new Exception("Error processing password");
            }
        }

        private string GenerateNameFromEmail(string email)
        {
            var name = email.Contains("@") ? email.Split('@')[0] : email;
            // Ensure name doesn't exceed 100 characters
            return name.Length > 100 ? name.Substring(0, 97) + "..." : name;
        }

        private bool IsValidRole(string role)
        {
            var validRoles = new[] { "student", "instructor" };
            return validRoles.Contains(role.ToLower());
        }

        private string GenerateJwtToken(User user)
        {
            try
            {
                var jwtKey = _configuration["Jwt:Key"];
                var jwtIssuer = _configuration["Jwt:Issuer"];
                var jwtAudience = _configuration["Jwt:Audience"];
                var jwtExpiryInMinutes = _configuration.GetValue<int>("Jwt:ExpiryInMinutes", 60);

                if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
                {
                    _logger.LogError("JWT configuration is incomplete");
                    throw new InvalidOperationException("JWT configuration is incomplete");
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, user.Role)
                };

                var token = new JwtSecurityToken(
                    issuer: jwtIssuer,
                    audience: jwtAudience,
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(jwtExpiryInMinutes),
                    signingCredentials: credentials
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating JWT token for user: {Email}", user.Email);
                throw;
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto model)
        {
            try
            {
                _logger.LogInformation("Registration attempt received. Model: {@Model}", new { 
                    model.Email, 
                    model.Role, 
                    model.FirstName, 
                    model.LastName,
                    HasPassword = !string.IsNullOrEmpty(model.Password)
                });

                // Log model state
                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage)
                        .ToList();
                    
                    _logger.LogWarning("Invalid registration model state. Errors: {@Errors}", errors);
                    return BadRequest(new { message = "Invalid input data", errors });
                }

                // Check if user already exists
                if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                {
                    _logger.LogWarning("Registration failed - Email already exists: {Email}", model.Email);
                    return BadRequest(new { message = "Email already registered" });
                }

                // Validate role
                if (!IsValidRole(model.Role))
                {
                    _logger.LogWarning("Invalid role specified: {Role}", model.Role);
                    return BadRequest(new { message = "Invalid role specified" });
                }

                try
                {
                    // Create user
                    var user = new User
                    {
                        Email = model.Email,
                        Name = $"{model.FirstName} {model.LastName}",
                        Role = model.Role,
                        PasswordHash = HashPassword(model.Password)
                    };

                    _logger.LogInformation("Attempting to add user to database: {@User}", new { 
                        user.Email, 
                        user.Role, 
                        user.Name 
                    });

                    // Add user to database
                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("User registered successfully: {Email}", model.Email);

                    // Generate JWT token
                    var token = GenerateJwtToken(user);
                    return Ok(new { 
                        token,
                        id = user.UserId,
                        email = user.Email,
                        role = user.Role
                    });
                }
                catch (DbUpdateException dbEx)
                {
                    _logger.LogError(dbEx, "Database error during user registration: {Message}", dbEx.Message);
                    if (dbEx.InnerException != null)
                    {
                        _logger.LogError("Inner exception: {Message}", dbEx.InnerException.Message);
                    }
                    return StatusCode(500, new { message = "Database error during registration" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user registration for email: {Email}. Error: {Message}", 
                    model.Email, ex.Message);
                if (ex.InnerException != null)
                {
                    _logger.LogError("Inner exception: {Message}", ex.InnerException.Message);
                }
                return StatusCode(500, new { 
                    message = "An error occurred during registration",
                    error = ex.Message
                });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
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
}
