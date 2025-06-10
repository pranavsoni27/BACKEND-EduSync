using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EduSyncAPI.Data;
using EduSyncAPI.Models;
using EduSyncAPI.DTOs.Results;

namespace EduSyncAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ResultsController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ResultsController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<GetResultDto>>> GetResults()
        {
            var results = await _context.AssessmentResults.ToListAsync();

            var dtoList = results.Select(r => new GetResultDto
            {
                ResultId = r.ResultId,
                AssessmentId = r.AssessmentId,
                UserId = r.UserId,
                Score = r.Score,
                MaxScore = r.MaxScore,
                SubmittedAt = r.SubmittedAt
            }).ToList();

            return Ok(dtoList);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<GetResultDto>> GetResult(Guid id)
        {
            var r = await _context.AssessmentResults.FindAsync(id);

            if (r == null)
            {
                return NotFound();
            }

            var dto = new GetResultDto
            {
                ResultId = r.ResultId,
                AssessmentId = r.AssessmentId,
                UserId = r.UserId,
                Score = r.Score,
                MaxScore = r.MaxScore,
                SubmittedAt = r.SubmittedAt
            };

            return Ok(dto);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> PutResult(Guid id, UpdateResultDto dto)
        {
            var result = await _context.AssessmentResults.FindAsync(id);

            if (result == null)
            {
                return NotFound();
            }

            if (dto.AssessmentId.HasValue)
                result.AssessmentId = dto.AssessmentId.Value;
            if (dto.UserId.HasValue)
                result.UserId = dto.UserId.Value;
            if (dto.Score.HasValue)
                result.Score = dto.Score.Value;
            if (dto.MaxScore.HasValue)
                result.MaxScore = dto.MaxScore.Value;
            if (dto.SubmittedAt.HasValue)
                result.SubmittedAt = dto.SubmittedAt.Value;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ResultExists(id))
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

        [HttpPost]
        public async Task<ActionResult<GetResultDto>> PostResult(CreateResultDto dto)
        {
            var result = new AssessmentResult
            {
                ResultId = Guid.NewGuid(),
                AssessmentId = dto.AssessmentId,
                UserId = dto.UserId,
                Score = dto.Score,
                MaxScore = dto.MaxScore,
                SubmittedAt = dto.SubmittedAt
            };

            _context.AssessmentResults.Add(result);
            await _context.SaveChangesAsync();

            var getDto = new GetResultDto
            {
                ResultId = result.ResultId,
                AssessmentId = result.AssessmentId,
                UserId = result.UserId,
                Score = result.Score,
                MaxScore = result.MaxScore,
                SubmittedAt = result.SubmittedAt
            };

            return CreatedAtAction(nameof(GetResult), new { id = result.ResultId }, getDto);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteResult(Guid id)
        {
            var result = await _context.AssessmentResults.FindAsync(id);

            if (result == null)
            {
                return NotFound();
            }

            _context.AssessmentResults.Remove(result);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool ResultExists(Guid id)
        {
            return _context.AssessmentResults.Any(e => e.ResultId == id);
        }
    }
}
