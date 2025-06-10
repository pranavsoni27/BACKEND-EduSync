using System;

namespace EduSyncAPI.DTOs.Results
{
    public class GetResultDto
    {
        public Guid ResultId { get; set; }
        public Guid AssessmentId { get; set; }
        public Guid UserId { get; set; }
        public int Score { get; set; }
        public int MaxScore { get; set; }
        public DateTime SubmittedAt { get; set; }
    }
}
