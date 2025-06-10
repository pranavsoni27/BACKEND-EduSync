using EduSyncAPI.Data;
using EduSyncAPI.DTOs.Courses;
using EduSyncAPI.DTOs.Assessments;
using EduSyncAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace EduSyncAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CoursesController : ControllerBase
    {
        private readonly AppDbContext _context;

        public CoursesController(AppDbContext context)
        {
            _context = context;
        }

        // --- Courses Endpoints ---

        [HttpGet]
        public async Task<ActionResult<IEnumerable<GetCourseDto>>> GetCourses()
        {
            var courses = await _context.Courses
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

        [HttpGet("{id}")]
        public async Task<ActionResult<GetCourseDto>> GetCourse(Guid id)
        {
            var course = await _context.Courses.FindAsync(id);
            if (course == null)
                return NotFound();

            var courseDto = new GetCourseDto
            {
                CourseId = course.CourseId,
                Title = course.Title,
                Description = course.Description,
                InstructorId = course.InstructorId,
                MediaUrl = course.MediaUrl
            };

            return Ok(courseDto);
        }

        [HttpPost]
        public async Task<ActionResult<GetCourseDto>> CreateCourse(CreateCourseDto createCourseDto)
        {
            var course = new Course
            {
                Title = createCourseDto.Title,
                Description = createCourseDto.Description,
                InstructorId = createCourseDto.InstructorId,
                MediaUrl = createCourseDto.MediaUrl
            };

            _context.Courses.Add(course);
            await _context.SaveChangesAsync();

            var courseDto = new GetCourseDto
            {
                CourseId = course.CourseId,
                Title = course.Title,
                Description = course.Description,
                InstructorId = course.InstructorId,
                MediaUrl = course.MediaUrl
            };

            return CreatedAtAction(nameof(GetCourse), new { id = course.CourseId }, courseDto);
        }

        // --- Course Content Endpoints ---

        // POST: api/courses/{courseId}/content
        [HttpPost("{courseId}/content")]
        public async Task<IActionResult> AddContent(Guid courseId, [FromBody] CreateContentDto contentDto)
        {
            try
            {
                var course = await _context.Courses.FindAsync(courseId);
                if (course == null)
                    return NotFound(new { message = "Course not found" });

                var content = new CourseContent
                {
                    ContentId = Guid.NewGuid(),
                    CourseId = courseId,
                    Title = contentDto.Title,
                    Description = contentDto.Description,
                    Url = contentDto.Url,
                    Type = contentDto.Type,
                    Order = await _context.CourseContents.CountAsync(c => c.CourseId == courseId),
                    CreatedAt = DateTime.UtcNow
                };

                _context.CourseContents.Add(content);
                await _context.SaveChangesAsync();

                return Ok(new GetCourseContentDto
                {
                    ContentId = content.ContentId,
                    Title = content.Title,
                    Description = content.Description,
                    Url = content.Url,
                    Type = content.Type,
                    Order = content.Order
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while adding content", error = ex.Message });
            }
        }

        // GET: api/courses/{courseId}/content
        [HttpGet("{courseId}/content")]
        public async Task<ActionResult<IEnumerable<CourseContent>>> GetContent(Guid courseId)
        {
            var contents = await _context.CourseContents
                .Where(c => c.CourseId == courseId)
                .ToListAsync();

            return Ok(contents);
        }

        // --- MCQ Assessment Endpoints ---

        public class McqQuestionDto
        {
            public string Text { get; set; }
            public List<string> Options { get; set; }
            public int CorrectOptionIndex { get; set; }
            public int Marks { get; set; }
        }

        public class CreateAssessmentDto
        {
            public Guid CourseId { get; set; }
            public string Title { get; set; }
            public List<McqQuestionDto> Questions { get; set; }
            public int Duration { get; set; }
        }

        // POST: api/courses/{courseId}/assessments
        [HttpPost("{courseId}/assessments")]
        public async Task<ActionResult<GetAssessmentDto>> CreateAssessment(Guid courseId, CreateAssessmentDto dto)
        {
            try
            {
                var course = await _context.Courses.FindAsync(courseId);
                if (course == null)
                {
                    return NotFound(new { message = "Course not found" });
                }

                if (dto.Questions == null || !dto.Questions.Any())
                {
                    return BadRequest(new { message = "At least one question is required" });
                }

                var questions = dto.Questions.Select(q => new Question
                {
                    Text = q.Text,
                    Options = q.Options,
                    CorrectOptionIndex = q.CorrectOptionIndex,
                    Marks = q.Marks
                }).ToList();

                var assessment = new Assessment
                {
                    AssessmentId = Guid.NewGuid(),
                    Title = dto.Title,
                    Duration = dto.Duration,
                    CourseId = courseId,
                    Questions = questions,
                    MaxScore = questions.Sum(q => q.Marks)
                };

                _context.Assessments.Add(assessment);
                await _context.SaveChangesAsync();

                var responseDto = new GetAssessmentDto
                {
                    AssessmentId = assessment.AssessmentId,
                    Title = assessment.Title,
                    Questions = assessment.Questions,
                    CourseId = assessment.CourseId,
                    MaxScore = assessment.MaxScore
                };

                return Ok(responseDto);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while creating the assessment", error = ex.Message });
            }
        }

        // GET: api/courses/{courseId}/assessments
        [HttpGet("{courseId}/assessments")]
        public async Task<ActionResult<IEnumerable<GetAssessmentDto>>> GetCourseAssessments(Guid courseId)
        {
            var assessments = await _context.Assessments
                .Where(a => a.CourseId == courseId)
                .Select(a => new GetAssessmentDto
                {
                    AssessmentId = a.AssessmentId,
                    Title = a.Title,
                    Questions = a.Questions,
                    CourseId = a.CourseId,
                    MaxScore = a.MaxScore
                })
                .ToListAsync();

            return Ok(assessments);
        }

        [HttpPost("{courseId}/join")]
        public async Task<IActionResult> JoinCourse(Guid courseId, [FromHeader(Name = "Authorization")] string authHeader)
        {
            try
            {
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized(new { message = "Invalid authorization header" });
                }

                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized(new { message = "User not authenticated" });
                }

                var user = await _context.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                {
                    return Unauthorized(new { message = "User not found" });
                }

                var course = await _context.Courses.FindAsync(courseId);
                if (course == null)
                {
                    return NotFound(new { message = "Course not found" });
                }

                var existingEnrollment = await _context.CourseEnrollments
                    .FirstOrDefaultAsync(e => e.CourseId == courseId && e.UserId == user.UserId);

                if (existingEnrollment != null)
                {
                    return BadRequest(new { message = "Already enrolled in this course" });
                }

                var enrollment = new CourseEnrollment
                {
                    EnrollmentId = Guid.NewGuid(),
                    CourseId = courseId,
                    UserId = user.UserId,
                    EnrollmentDate = DateTime.UtcNow
                };

                _context.CourseEnrollments.Add(enrollment);
                await _context.SaveChangesAsync();

                return Ok(new { message = "Successfully joined the course", enrollmentId = enrollment.EnrollmentId });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while joining the course", error = ex.Message });
            }
        }

        [HttpGet("{courseId}/contents")]
        public async Task<ActionResult<IEnumerable<GetCourseContentDto>>> GetCourseContents(Guid courseId)
        {
            var contents = await _context.CourseContents
                .Where(c => c.CourseId == courseId)
                .OrderBy(c => c.Order)
                .Select(c => new GetCourseContentDto
                {
                    ContentId = c.ContentId,
                    Title = c.Title,
                    Description = c.Description,
                    Type = c.Type,
                    Url = c.Url,
                    Order = c.Order
                })
                .ToListAsync();

            return Ok(contents);
        }

        [HttpGet("{courseId}/student-performance")]
        public async Task<ActionResult<IEnumerable<StudentPerformanceDto>>> GetStudentPerformance(Guid courseId)
        {
            try
            {
                var enrollments = await _context.CourseEnrollments
                    .Include(e => e.User)
                    .Where(e => e.CourseId == courseId)
                    .ToListAsync();

                var studentPerformance = new List<StudentPerformanceDto>();

                foreach (var enrollment in enrollments)
                {
                    var results = await _context.AssessmentResults
                        .Include(r => r.Assessment)
                        .Where(r => r.UserId == enrollment.UserId && r.Assessment.CourseId == courseId)
                        .Select(r => new AssessmentResultDto
                        {
                            AssessmentId = r.AssessmentId,
                            AssessmentTitle = r.Assessment.Title,
                            Score = r.Score,
                            MaxScore = r.MaxScore,
                            SubmittedAt = r.SubmittedAt
                        })
                        .ToListAsync();

                    studentPerformance.Add(new StudentPerformanceDto
                    {
                        UserId = enrollment.UserId,
                        UserName = enrollment.User.Name,
                        Email = enrollment.User.Email,
                        EnrollmentDate = enrollment.EnrollmentDate,
                        AssessmentResults = results
                    });
                }

                return Ok(studentPerformance);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while fetching student performance", error = ex.Message });
            }
        }

        public class StudentPerformanceDto
        {
            public Guid UserId { get; set; }
            public string UserName { get; set; }
            public string Email { get; set; }
            public DateTime EnrollmentDate { get; set; }
            public List<AssessmentResultDto> AssessmentResults { get; set; }
        }

        public class AssessmentResultDto
        {
            public Guid AssessmentId { get; set; }
            public string AssessmentTitle { get; set; }
            public int Score { get; set; }
            public int MaxScore { get; set; }
            public DateTime SubmittedAt { get; set; }
        }

        // Add more endpoints (update, delete, enroll, etc.) here if needed
    }
}
