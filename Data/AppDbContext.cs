using EduSyncAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using System.Text.Json;

namespace EduSyncAPI.Data
{
    public partial class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public virtual DbSet<CourseContent> CourseContents { get; set; }
        public virtual DbSet<Assessment> Assessments { get; set; }
        public virtual DbSet<Course> Courses { get; set; }
        public virtual DbSet<User> Users { get; set; }
        public virtual DbSet<CourseEnrollment> CourseEnrollments { get; set; }
        public virtual DbSet<AssessmentResult> AssessmentResults { get; set; }
        public virtual DbSet<QuestionResponse> QuestionResponses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var questionListConverter = new ValueConverter<List<Question>, string>(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null),
                v => JsonSerializer.Deserialize<List<Question>>(v, (JsonSerializerOptions)null) ?? new List<Question>()
            );

            modelBuilder.Entity<Assessment>(entity =>
            {
                entity.Property(e => e.AssessmentId).ValueGeneratedOnAdd();
                entity.Property(e => e.Questions)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions)null),
                        v => JsonSerializer.Deserialize<List<Question>>(v, (JsonSerializerOptions)null) ?? new List<Question>()
                    )
                    .HasColumnType("nvarchar(max)");
                entity.Property(e => e.Title).HasMaxLength(50).IsUnicode(false);
                entity.Property(e => e.MaxScore).IsRequired();
                entity.Property(e => e.Duration).IsRequired();
            });

            modelBuilder.Entity<Course>(entity =>
            {
                entity.Property(e => e.CourseId).ValueGeneratedOnAdd();
                entity.Property(e => e.Description).HasMaxLength(50).IsUnicode(false);
                entity.Property(e => e.MediaUrl).HasMaxLength(250).IsUnicode(false);  // increased max length here
                entity.Property(e => e.Title).HasMaxLength(50).IsUnicode(false);
                entity.Property(e => e.InstructorId).IsRequired();
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.UserId).ValueGeneratedOnAdd();
                entity.Property(e => e.Email).HasMaxLength(100).IsUnicode(false).IsRequired();
                entity.Property(e => e.Name).HasMaxLength(100).IsUnicode(false).IsRequired();
                entity.Property(e => e.PasswordHash).HasMaxLength(256).IsUnicode(false).IsRequired();
                entity.Property(e => e.Role).HasMaxLength(50).IsUnicode(false).IsRequired();
            });

            modelBuilder.Entity<AssessmentResult>(entity =>
            {
                entity.Property(e => e.ResultId).ValueGeneratedOnAdd();
                entity.Property(e => e.Score).IsRequired();
                entity.Property(e => e.MaxScore).IsRequired();
                entity.Property(e => e.SubmittedAt).IsRequired();
            });

            modelBuilder.Entity<QuestionResponse>(entity =>
            {
                entity.HasKey(e => e.ResponseId);
                entity.Property(e => e.ResponseId).ValueGeneratedOnAdd();
                entity.Property(e => e.QuestionIndex).IsRequired();
                entity.Property(e => e.SelectedOptionIndex).IsRequired();
                entity.Property(e => e.IsCorrect).IsRequired();
                entity.Property(e => e.MarksObtained).IsRequired();

                entity.HasOne(e => e.Result)
                    .WithMany(r => r.Responses)
                    .HasForeignKey(e => e.ResultId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Configure CourseEnrollment relationships
            modelBuilder.Entity<CourseEnrollment>()
                .HasOne(ce => ce.Course)
                .WithMany()
                .HasForeignKey(ce => ce.CourseId);

            modelBuilder.Entity<CourseEnrollment>()
                .HasOne(ce => ce.User)
                .WithMany()
                .HasForeignKey(ce => ce.UserId);

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
