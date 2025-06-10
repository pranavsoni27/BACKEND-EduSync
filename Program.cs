using EduSyncAPI.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// jwt
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"), sqlOptions =>
    {
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 3,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorNumbersToAdd: null);
    });
});

// CORS for frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy
            .WithOrigins("https://calm-sand-0920fd500.6.azurestaticapps.net")
            .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .WithHeaders("Content-Type", "Authorization", "Accept")
            .SetIsOriginAllowed(origin => true) // Allow all origins for now
            .AllowCredentials();
    });
});

// Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "EduSync API",
        Version = "v1",
        Description = "API for EduSync Learning Management System"
    });

    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
    c.CustomSchemaIds(type => type.FullName?.Replace("+", "_"));

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Add JWT configuration validation
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var jwtExpiry = builder.Configuration["Jwt:ExpiryInMinutes"];

// Log configuration values (without sensitive data)
builder.Logging.AddConsole();
var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();
logger.LogInformation("JWT Configuration - Issuer: {Issuer}, Audience: {Audience}, Expiry: {Expiry}", 
    jwtIssuer, jwtAudience, jwtExpiry);

// Validate JWT configuration
if (string.IsNullOrEmpty(jwtKey))
{
    logger.LogError("JWT:Key is missing or empty");
    throw new InvalidOperationException("JWT:Key is required");
}
if (jwtKey.Length < 32)
{
    logger.LogError("JWT:Key is too short (must be at least 32 characters)");
    throw new InvalidOperationException("JWT:Key must be at least 32 characters long");
}
if (string.IsNullOrEmpty(jwtIssuer))
{
    logger.LogError("JWT:Issuer is missing or empty");
    throw new InvalidOperationException("JWT:Issuer is required");
}
if (string.IsNullOrEmpty(jwtAudience))
{
    logger.LogError("JWT:Audience is missing or empty");
    throw new InvalidOperationException("JWT:Audience is required");
}
if (!int.TryParse(jwtExpiry, out var expiryMinutes) || expiryMinutes <= 0)
{
    logger.LogError("JWT:ExpiryInMinutes is invalid: {Expiry}", jwtExpiry);
    throw new InvalidOperationException("JWT:ExpiryInMinutes must be a positive integer");
}

logger.LogInformation("JWT configuration validated successfully");

var app = builder.Build();

// Configure logging
app.Logger.LogInformation("Application starting up...");
app.Logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("Content root path: {Path}", app.Environment.ContentRootPath);

// Database migration with better error handling
try
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<AppDbContext>();
    var dbLogger = services.GetRequiredService<ILogger<Program>>();
    
    dbLogger.LogInformation("Starting database migration...");
    dbLogger.LogInformation("Connection string: {ConnectionString}", 
        builder.Configuration.GetConnectionString("DefaultConnection")?.Substring(0, 20) + "...");
    
    // Test database connection
    if (context.Database.CanConnect())
    {
        dbLogger.LogInformation("Database connection test successful");
    }
    else
    {
        dbLogger.LogError("Cannot connect to database");
        throw new InvalidOperationException("Cannot connect to database");
    }
    
    context.Database.Migrate();
    dbLogger.LogInformation("Database migration completed successfully");
}
catch (Exception ex)
{
    var startupLogger = app.Logger;
    startupLogger.LogError(ex, "An error occurred during startup");
    if (ex.InnerException != null)
    {
        startupLogger.LogError("Inner exception: {Message}", ex.InnerException.Message);
        if (ex.InnerException.InnerException != null)
        {
            startupLogger.LogError("Inner inner exception: {Message}", 
                ex.InnerException.InnerException.Message);
        }
    }
    throw; // Rethrow to ensure the application doesn't start with a broken database
}

// Enable Swagger in development mode
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.Logger.LogInformation("Swagger enabled for development environment");
}

// Add CORS middleware before other middleware
app.UseCors("AllowFrontend");
app.Logger.LogInformation("CORS middleware configured");

// Add a middleware to handle CORS preflight
app.Use(async (context, next) =>
{
    try
    {
        context.Response.Headers.Append("Access-Control-Allow-Origin", 
            "https://calm-sand-0920fd500.6.azurestaticapps.net");
        context.Response.Headers.Append("Access-Control-Allow-Methods", 
            "GET, POST, PUT, DELETE, OPTIONS");
        context.Response.Headers.Append("Access-Control-Allow-Headers", 
            "Content-Type, Authorization, X-Requested-With");
        context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");
        context.Response.Headers.Append("Access-Control-Max-Age", "86400");

        if (context.Request.Method == "OPTIONS")
        {
            context.Response.StatusCode = 200;
            return;
        }

        await next();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error in CORS middleware");
        throw;
    }
});

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
    app.Logger.LogInformation("HTTPS redirection enabled");
}

// Adding middlewares
app.UseAuthentication();
app.UseAuthorization();
app.Logger.LogInformation("Authentication and authorization middleware configured");

// Map controllers
app.MapControllers();
app.Logger.LogInformation("Controllers mapped");

// Run the application
app.Logger.LogInformation("Application startup complete, beginning to listen for requests");
app.Run();
