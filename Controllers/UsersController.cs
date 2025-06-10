using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EduSyncAPI.Data;
using EduSyncAPI.Models;
using EduSyncAPI.DTOs.Users;
using EduSyncAPI.DTOs.Courses;
using EduSyncAPI.DTOs.Results;

namespace EduSyncAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _context;

        public UsersController(AppDbContext context)
        {
            _context = context;
        }

        // GET: api/Users
        [HttpGet]
        public async Task<ActionResult<IEnumerable<GetUserDto>>> GetUsers()
        {
            var users = await _context.Users.ToListAsync();

            var dtoList = users.Select(u => new GetUserDto
            {
                UserId = u.UserId,
                Name = u.Name,
                Email = u.Email,
                Role = u.Role
            }).ToList();

            return Ok(dtoList);
        }

        // GET: api/Users/5
        [HttpGet("{id}")]
        public async Task<ActionResult<GetUserDto>> GetUser(Guid id)
        {
            var u = await _context.Users.FindAsync(id);

            if (u == null)
            {
                return NotFound();
            }

            var dto = new GetUserDto
            {
                UserId = u.UserId,
                Name = u.Name,
                Email = u.Email,
                Role = u.Role
            };

            return Ok(dto);
        }

        // PUT: api/Users/5
        [HttpPut("{id}")]
        public async Task<IActionResult> PutUser(Guid id, UpdateUserDto dto)
        {
            var user = await _context.Users.FindAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            user.Name = dto.Name;
            user.Email = dto.Email;
            user.PasswordHash = dto.PasswordHash;
            user.Role = dto.Role;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Users
        [HttpPost]
        public async Task<ActionResult<GetUserDto>> PostUser(CreateUserDto dto)
        {
            var user = new User
            {
                UserId = Guid.NewGuid(),
                Name = dto.Name,
                Email = dto.Email,
                PasswordHash = dto.PasswordHash,
                Role = dto.Role
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var resultDto = new GetUserDto
            {
                UserId = user.UserId,
                Name = user.Name,
                Email = user.Email,
                Role = user.Role
            };

            return CreatedAtAction(nameof(GetUser), new { id = user.UserId }, resultDto);
        }

        // DELETE: api/Users/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // GET: api/users/{userId}/courses
        [HttpGet("{userId}/courses")]
        public async Task<ActionResult<IEnumerable<GetCourseDto>>> GetJoinedCourses(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                var courses = await _context.Courses
                    .Where(c => c.InstructorId == userId || _context.CourseEnrollments.Any(e => e.CourseId == c.CourseId && e.UserId == userId))
                    .Select(course => new GetCourseDto
                    {
                        CourseId = course.CourseId,
                        Title = course.Title,
                        Description = course.Description,
                        InstructorId = course.InstructorId,
                        MediaUrl = course.MediaUrl
                    })
                    .ToListAsync();

                return Ok(courses);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while fetching joined courses", error = ex.Message });
            }
        }

        // GET: api/users/{userId}/results
        [HttpGet("{userId}/results")]
        public async Task<ActionResult<IEnumerable<GetResultDto>>> GetUserResults(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                var results = await _context.AssessmentResults
                    .Where(r => r.UserId == userId)
                    .Select(r => new GetResultDto
                    {
                        ResultId = r.ResultId,
                        AssessmentId = r.AssessmentId,
                        UserId = r.UserId,
                        Score = r.Score,
                        MaxScore = r.MaxScore,
                        SubmittedAt = r.SubmittedAt
                    })
                    .ToListAsync();

                return Ok(results);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while fetching user results", error = ex.Message });
            }
        }

        private bool UserExists(Guid id)
        {
            return _context.Users.Any(e => e.UserId == id);
        }
    }
}
