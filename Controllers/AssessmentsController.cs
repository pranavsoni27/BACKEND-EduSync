using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EduSyncAPI.Data;
using EduSyncAPI.Models;
using EduSyncAPI.DTOs.Assessments;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace EduSyncAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AssessmentsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly JsonSerializerOptions _jsonOptions;

        public AssessmentsController(AppDbContext context)
        {
            _context = context;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            };
        }

        // GET: api/Assessments
        [HttpGet]
        public async Task<ActionResult<IEnumerable<GetAssessmentDto>>> GetAssessments()
        {
            try
            {
                var assessments = await _context.Assessments
                    // .Include(a => a.Questions) // Removed for owned type compatibility
                    .ToListAsync();

                var dtoList = assessments.Select(a => new GetAssessmentDto
                {
                    AssessmentId = a.AssessmentId,
                    CourseId = a.CourseId,
                    Title = a.Title ?? string.Empty,
                    Questions = a.Questions,
                    MaxScore = a.MaxScore
                }).ToList();

                return Ok(dtoList);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // GET: api/Assessments/5
        [HttpGet("{id}")]
        public async Task<ActionResult<GetAssessmentDto>> GetAssessment(Guid id)
        {
            var assessment = await _context.Assessments
                // .Include(a => a.Questions) // Removed for owned type compatibility
                .FirstOrDefaultAsync(a => a.AssessmentId == id);

            if (assessment == null)
            {
                return NotFound();
            }

            var dto = new GetAssessmentDto
            {
                AssessmentId = assessment.AssessmentId,
                CourseId = assessment.CourseId,
                Title = assessment.Title ?? string.Empty,
                Questions = assessment.Questions,
                MaxScore = assessment.MaxScore
            };

            return Ok(dto);
        }

        // PUT: api/Assessments/5
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateAssessment(Guid id, Assessment assessment)
        {
            if (id != assessment.AssessmentId)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            _context.Entry(assessment).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!AssessmentExists(id))
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

        // POST: api/Assessments
        [HttpPost]
        public async Task<ActionResult<Assessment>> CreateAssessment(Assessment assessment)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            _context.Assessments.Add(assessment);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetAssessment), new { id = assessment.AssessmentId }, assessment);
        }

        // DELETE: api/Assessments/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteAssessment(Guid id)
        {
            var assessment = await _context.Assessments.FindAsync(id);
            if (assessment == null)
            {
                return NotFound();
            }

            _context.Assessments.Remove(assessment);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpPost("{id}/submit")]
        public async Task<ActionResult<AssessmentResult>> SubmitAssessment(Guid id, [FromBody] List<int> answers)
        {
            try
            {
                Console.WriteLine($"Submitting assessment {id} with {answers?.Count ?? 0} answers");
                Console.WriteLine($"Answers received: {string.Join(", ", answers ?? new List<int>())}");

                var assessment = await _context.Assessments
                    .FirstOrDefaultAsync(a => a.AssessmentId == id);

                if (assessment == null)
                {
                    Console.WriteLine($"Assessment not found with ID: {id}");
                    return NotFound(new { message = "Assessment not found" });
                }

                Console.WriteLine($"Found assessment: {assessment.Title} with {assessment.Questions?.Count ?? 0} questions");

                if (answers == null)
                {
                    Console.WriteLine("Answers array is null");
                    return BadRequest(new { message = "Answers cannot be null" });
                }

                if (answers.Count != assessment.Questions.Count)
                {
                    Console.WriteLine($"Mismatch in answer count. Received: {answers.Count}, Expected: {assessment.Questions.Count}");
                    return BadRequest(new { message = $"Number of answers ({answers.Count}) does not match number of questions ({assessment.Questions.Count})" });
                }

                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    Console.WriteLine("User ID not found in claims");
                    return Unauthorized(new { message = "User not authenticated" });
                }

                Console.WriteLine($"Processing submission for user: {userId}");

                // Check if user has already submitted this assessment
                var existingResult = await _context.AssessmentResults
                    .FirstOrDefaultAsync(r => r.AssessmentId == id && r.UserId == Guid.Parse(userId));

                if (existingResult != null)
                {
                    Console.WriteLine($"User {userId} has already submitted assessment {id}");
                    return BadRequest(new { message = "You have already submitted this assessment" });
                }

                var score = 0;
                var responses = new List<QuestionResponse>();

                Console.WriteLine("Processing answers and calculating score...");
                for (int i = 0; i < assessment.Questions.Count; i++)
                {
                    var question = assessment.Questions[i];
                    var isCorrect = answers[i] == question.CorrectOptionIndex;
                    var marksObtained = isCorrect ? question.Marks : 0;
                    score += marksObtained;

                    Console.WriteLine($"Question {i + 1}: Selected {answers[i]}, Correct {question.CorrectOptionIndex}, Marks: {marksObtained}");

                    responses.Add(new QuestionResponse
                    {
                        ResponseId = Guid.NewGuid(),
                        QuestionIndex = i,
                        SelectedOptionIndex = answers[i],
                        IsCorrect = isCorrect,
                        MarksObtained = marksObtained
                    });
                }

                Console.WriteLine($"Total score calculated: {score}/{assessment.MaxScore}");

                var result = new AssessmentResult
                {
                    ResultId = Guid.NewGuid(),
                    AssessmentId = id,
                    UserId = Guid.Parse(userId),
                    Score = score,
                    MaxScore = assessment.MaxScore,
                    SubmittedAt = DateTime.UtcNow
                };

                Console.WriteLine("Saving assessment result...");
                _context.AssessmentResults.Add(result);
                await _context.SaveChangesAsync();

                // Now add the responses after the result is saved
                foreach (var response in responses)
                {
                    response.ResultId = result.ResultId;
                }
                _context.QuestionResponses.AddRange(responses);
                await _context.SaveChangesAsync();

                Console.WriteLine("Assessment result and responses saved successfully");

                return Ok(new
                {
                    resultId = result.ResultId,
                    score = result.Score,
                    maxScore = result.MaxScore,
                    submittedAt = result.SubmittedAt
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error submitting assessment: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                    Console.WriteLine($"Inner Exception Stack Trace: {ex.InnerException.StackTrace}");
                }
                return StatusCode(500, new { message = "An error occurred while submitting the assessment", error = ex.Message });
            }
        }

        [HttpPost("{id}/start")]
        public async Task<ActionResult<GetAssessmentDto>> StartAssessment(Guid id)
        {
            try
            {
                Console.WriteLine($"Starting assessment with ID: {id}");

                // Get the assessment without trying to include Questions
                var assessment = await _context.Assessments
                    .AsNoTracking()
                    .FirstOrDefaultAsync(a => a.AssessmentId == id);

                if (assessment == null)
                {
                    Console.WriteLine($"Assessment not found with ID: {id}");
                    return NotFound(new { message = "Assessment not found" });
                }

                Console.WriteLine($"Found assessment: {assessment.Title}");

                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    Console.WriteLine("User not authenticated");
                    return Unauthorized(new { message = "User not authenticated" });
                }

                Console.WriteLine($"User ID: {userId}");

                // Check if user has already completed this assessment
                var existingResult = await _context.AssessmentResults
                    .AsNoTracking()
                    .FirstOrDefaultAsync(r => r.AssessmentId == id && r.UserId == Guid.Parse(userId));

                if (existingResult != null)
                {
                    Console.WriteLine($"User has already completed assessment: {id}");
                    return BadRequest(new { message = "You have already completed this assessment" });
                }

                if (assessment.Questions == null || !assessment.Questions.Any())
                {
                    Console.WriteLine($"Assessment {id} has no questions");
                    return BadRequest(new { message = "Assessment has no questions" });
                }

                Console.WriteLine($"Assessment has {assessment.Questions.Count} questions");

                // Validate each question
                foreach (var question in assessment.Questions)
                {
                    if (string.IsNullOrEmpty(question.Text))
                    {
                        Console.WriteLine($"A question has empty text");
                        return BadRequest(new { message = "Assessment contains invalid questions" });
                    }

                    if (question.Options == null || !question.Options.Any())
                    {
                        Console.WriteLine($"A question has no options");
                        return BadRequest(new { message = "Assessment contains questions without options" });
                    }
                }

                var dto = new GetAssessmentDto
                {
                    AssessmentId = assessment.AssessmentId,
                    CourseId = assessment.CourseId,
                    Title = assessment.Title,
                    Questions = assessment.Questions,
                    MaxScore = assessment.MaxScore,
                    Duration = assessment.Duration
                };

                Console.WriteLine($"Returning assessment DTO with {dto.Questions.Count} questions");
                return Ok(dto);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in StartAssessment: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                    Console.WriteLine($"Inner Exception Stack Trace: {ex.InnerException.StackTrace}");
                }
                return StatusCode(500, new { message = "An error occurred while starting the assessment", error = ex.Message });
            }
        }

        private bool AssessmentExists(Guid id)
        {
            return _context.Assessments.Any(e => e.AssessmentId == id);
        }
    }
}
