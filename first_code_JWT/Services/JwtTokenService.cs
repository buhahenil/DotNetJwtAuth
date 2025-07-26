using first_code_JWT.Models;
using first_code_JWT.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace first_code_JWT.Services
{
    /// <summary>
    /// Provides methods to generate JWT tokens, refresh tokens,
    /// and extract user information from expired tokens.
    /// </summary>
    public class JwtTokenService : IJwtTokenService
    {
        private readonly JwtSettings _jwtSettings;

        /// <summary>
        /// Constructor to inject JWT settings from configuration.
        /// </summary>
        /// <param name="jwtSettings">Configuration settings for JWT.</param>
        public JwtTokenService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        /// <summary>
        /// Generates a JWT access token for the specified user.
        /// </summary>
        /// <param name="user">The user object containing claims data.</param>
        /// <returns>A signed JWT token as a string.</returns>
        public string GenerateToken(User user)
        {
            // Define user claims for identity and role
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            // Create a symmetric security key from the secret key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));

            // Define signing credentials using the key and HMAC SHA256 algorithm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create the token with issuer, audience, claims, expiration, and signing credentials
            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                signingCredentials: creds);

            // Convert the token object into a string and return it
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Generates a secure random refresh token as a Base64 string.
        /// </summary>
        /// <returns>Refresh token string.</returns>
        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes); // Fill byte array with secure random values
            return Convert.ToBase64String(randomBytes);
        }

        /// <summary>
        /// Extracts the ClaimsPrincipal from an expired JWT token.
        /// Used during the refresh token flow.
        /// </summary>
        /// <param name="token">The expired JWT access token.</param>
        /// <returns>The principal if the token is valid, even if expired; otherwise null.</returns>
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            // Set token validation parameters (ignore lifetime check)
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = false, // Do NOT validate expiry here
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key))
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                // Validate the token and extract principal (even if token is expired)
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                // Ensure the token is of expected type and algorithm
                if (securityToken is not JwtSecurityToken jwtToken ||
                    !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                // Token is invalid or malformed
                return null;
            }
        }
    }
}
