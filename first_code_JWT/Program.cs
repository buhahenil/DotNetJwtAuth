using first_code_JWT.Data;
using first_code_JWT.Services;
using first_code_JWT.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// =====================================
// Configure Entity Framework & Database
// =====================================
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// =====================================
// Bind JWT Settings from appsettings.json
// =====================================
builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JwtSettings"));

// Get strongly typed JwtSettings instance
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
var key = Encoding.UTF8.GetBytes(jwtSettings.Key);

// =====================================
// Configure JWT Authentication
// =====================================
builder.Services.AddAuthentication(options =>
{
    // Set the default authentication scheme to JWT bearer
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Set JWT token validation parameters
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true, // Validate expiration
        ValidateIssuerSigningKey = true, // Validate signature
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

// =====================================
// Register Application Services
// =====================================
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>(); // Custom JWT logic
builder.Services.AddControllers();                               // Add controller support
builder.Services.AddEndpointsApiExplorer();                      // Enable minimal API exploration
builder.Services.AddSwaggerGen();                                // Swagger for API documentation

var app = builder.Build();

// =====================================
// Configure Middleware Pipeline
// =====================================
app.UseSwagger();         // Enable Swagger middleware
app.UseSwaggerUI();       // Enable Swagger UI

app.UseHttpsRedirection(); // Force HTTPS requests

app.UseAuthentication();   // Add JWT Authentication middleware
app.UseAuthorization();    // Add Authorization middleware

app.MapControllers();      // Map attribute-routed controllers

app.Run();                 // Run the application
