using System;

namespace EduSyncAPI.DTOs.Results
{
    public class UpdateResultDto
    {
        public Guid? AssessmentId { get; set; }
        public Guid? UserId { get; set; }
        public int? Score { get; set; }
        public int? MaxScore { get; set; }
        public DateTime? SubmittedAt { get; set; }
    }
}
