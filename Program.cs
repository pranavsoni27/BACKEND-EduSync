using EduSyncAPI.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add configuration sources
builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.SetMinimumLevel(LogLevel.Information);

// Log environment and configuration
var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();
logger.LogInformation("Starting application in {Environment} environment", builder.Environment.EnvironmentName);

// Add services to the container
try
{
    // Configure CORS
    var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? 
        new[] { "https://calm-sand-0920fd500.6.azurestaticapps.net" };
    
    logger.LogInformation("Configuring CORS with origins: {Origins}", string.Join(", ", corsOrigins));
    
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigins", policy =>
        {
            policy.WithOrigins(corsOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        });
    });

    // Configure database
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    if (string.IsNullOrEmpty(connectionString))
    {
        throw new InvalidOperationException("Connection string 'DefaultConnection' not found in configuration.");
    }
    logger.LogInformation("Using database connection string: {ConnectionString}", 
        connectionString.Replace(connectionString.Split(';').FirstOrDefault(s => s.Contains("Password=")) ?? "", "Password=*****"));

    builder.Services.AddDbContext<AppDbContext>(options =>
    {
        options.UseSqlServer(connectionString, sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 3,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null);
        });
    });

    // Configure JWT
    var jwtKey = builder.Configuration["Jwt:Key"];
    var jwtIssuer = builder.Configuration["Jwt:Issuer"];
    var jwtAudience = builder.Configuration["Jwt:Audience"];
    var jwtExpiryInMinutes = builder.Configuration.GetValue<int>("Jwt:ExpiryInMinutes", 60);

    if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
    {
        throw new InvalidOperationException("JWT configuration is incomplete. Please check Jwt:Key, Jwt:Issuer, and Jwt:Audience settings.");
    }

    logger.LogInformation("JWT configured with Issuer: {Issuer}, Audience: {Audience}, Expiry: {Expiry} minutes",
        jwtIssuer, jwtAudience, jwtExpiryInMinutes);

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtIssuer,
                ValidAudience = jwtAudience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew = TimeSpan.Zero
            };
        });

    // Add other services
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    // Configure the HTTP request pipeline
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    // Use CORS before other middleware
    app.UseCors("AllowSpecificOrigins");

    // Add custom middleware for CORS preflight
    app.Use(async (context, next) =>
    {
        if (context.Request.Method == "OPTIONS")
        {
            logger.LogInformation("Handling OPTIONS request for path: {Path}", context.Request.Path);
            context.Response.Headers.Append("Access-Control-Allow-Origin", 
                corsOrigins.Contains(context.Request.Headers["Origin"].ToString()) 
                    ? context.Request.Headers["Origin"].ToString() 
                    : corsOrigins[0]);
            context.Response.Headers.Append("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            context.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
            context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");
            context.Response.Headers.Append("Access-Control-Max-Age", "86400");
            context.Response.StatusCode = 200;
            return;
        }
        await next();
    });

    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();

    // Test database connection
    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        try
        {
            logger.LogInformation("Testing database connection...");
            await dbContext.Database.CanConnectAsync();
            logger.LogInformation("Database connection successful");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Database connection failed");
            throw;
        }
    }

    app.Run();
}
catch (Exception ex)
{
    logger.LogError(ex, "Application startup failed");
    throw;
}
