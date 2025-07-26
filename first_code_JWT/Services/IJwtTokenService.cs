using first_code_JWT.Models;
using System.Security.Claims;

namespace first_code_JWT.Services
{
    /// <summary>
    /// Interface defining methods for generating and validating JWT and refresh tokens.
    /// </summary>
    public interface IJwtTokenService
    {
        /// <summary>
        /// Generates a JWT access token for the specified user.
        /// </summary>
        /// <param name="user">The user for whom the token is being generated.</param>
        /// <returns>A signed JWT token string.</returns>
        string GenerateToken(User user);

        /// <summary>
        /// Generates a secure random refresh token.
        /// </summary>
        /// <returns>A new refresh token string.</returns>
        string GenerateRefreshToken();

        /// <summary>
        /// Retrieves the claims principal (user identity) from an expired JWT token.
        /// Used for validating the user during token refresh.
        /// </summary>
        /// <param name="token">The expired JWT token.</param>
        /// <returns>The claims principal if token is valid; otherwise, null.</returns>
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
