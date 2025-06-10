using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace EduSyncAPI.Data
{
    public class ApplicationDbContext : DbContext
    {
        private readonly ILogger<ApplicationDbContext> _logger;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, ILogger<ApplicationDbContext> logger)
            : base(options)
        {
            _logger = logger;
            _logger.LogInformation("ApplicationDbContext initialized with connection string: {ConnectionString}", 
                Database.GetConnectionString());
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            try
            {
                // Test the database connection
                if (Database.CanConnect())
                {
                    _logger.LogInformation("Successfully connected to database");
                }
                else
                {
                    _logger.LogWarning("Could not connect to database");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing database connection");
            }
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Attempting to save changes to database");
                var result = await base.SaveChangesAsync(cancellationToken);
                _logger.LogInformation("Successfully saved {Count} changes to database", result);
                return result;
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Database update error: {Message}", ex.Message);
                if (ex.InnerException != null)
                {
                    _logger.LogError("Inner exception: {Message}", ex.InnerException.Message);
                }
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving changes to database: {Message}", ex.Message);
                throw;
            }
        }
    }
} 