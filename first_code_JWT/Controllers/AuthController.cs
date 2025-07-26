using first_code_JWT.DTOs;
using first_code_JWT.Models;
using first_code_JWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using first_code_JWT.Data;

namespace first_code_JWT.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly PasswordHasher<User> _passwordHasher;

        // Constructor to inject dependencies: DbContext and JWT token service
        public AuthController(AppDbContext context, IJwtTokenService jwtTokenService)
        {
            _context = context;
            _jwtTokenService = jwtTokenService;
            _passwordHasher = new PasswordHasher<User>();
        }

        // ===============================
        // Register new user (POST: /api/auth/register)
        // ===============================
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto dto)
        {
            try
            {
                // Check if username or email already exists
                if (await _context.Users.AnyAsync(u => u.Username == dto.Username || u.Email == dto.Email))
                    return BadRequest("Username or Email already exists.");

                // Create new User entity
                var user = new User
                {
                    Username = dto.Username,
                    Email = dto.Email
                };

                // Hash and store the password securely
                user.PasswordHash = _passwordHasher.HashPassword(user, dto.Password);

                // Save user to the database
                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                return Ok("User registered successfully.");
            }
            catch (Exception ex)
            {
                // Handle errors
                return StatusCode(500, $"Registration failed: {ex.Message}");
            }
        }

        // ===============================
        // User login (POST: /api/auth/login)
        // ===============================
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Retrieve user by username
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
                return Unauthorized("Invalid username or password");

            // Verify the password hash
            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result != PasswordVerificationResult.Success)
                return Unauthorized("Invalid username or password");

            // Generate JWT token and refresh token
            var token = _jwtTokenService.GenerateToken(user);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();

            // Store refresh token and expiry
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(60);
            await _context.SaveChangesAsync();

            // Return tokens to client
            return Ok(new
            {
                Token = token,
                RefreshToken = refreshToken
            });
        }

        // ===============================
        // Refresh JWT token (POST: /api/auth/refresh-token)
        // ===============================
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            // Extract username from expired token
            var principal = _jwtTokenService.GetPrincipalFromExpiredToken(request.Token);
            var username = principal?.Identity?.Name;

            // Validate user and refresh token
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user == null ||
                user.RefreshToken != request.RefreshToken ||
                user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Unauthorized();
            }

            // Generate new tokens
            var newAccessToken = _jwtTokenService.GenerateToken(user);
            var newRefreshToken = _jwtTokenService.GenerateRefreshToken();

            // Update tokens in the database
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(60);
            await _context.SaveChangesAsync();

            // Return new tokens
            return Ok(new
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        // ===============================
        // Protected endpoint (GET: /api/auth/secure-data)
        // ===============================
        [HttpGet("secure-data")]
        [Authorize] // Requires valid JWT token
        public IActionResult GetSecureData()
        {
            // Only accessible to authenticated users
            return Ok("This is protected data only visible to authenticated users.");
        }
    }
}
