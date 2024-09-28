using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace API_lvl_app.Models
{
    public class AuthService
    {
        private readonly HRIS_TX2Context _context;
        private readonly IConfiguration _configuration;

        public AuthService(HRIS_TX2Context context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<string> AuthenticateWithTokenAsync(string token)
        {
            // Validate the token
            var principal = ValidateJwtToken(token);
            if (principal == null)
            {
                return "Invalid or expired token";
            }

            var userId = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            // Find the user with this token
            var user = await _context.Data_User_Apps.SingleOrDefaultAsync(u => u.personID == userId && u.AccessToken == token);

            if (user == null)
            {
                return "Invalid token or user not found";
            }

            if (IsTokenExpired(principal))
            {
                var newToken = GenerateNewToken(userId);

                user.AccessToken = newToken;
                await _context.SaveChangesAsync();

                return $"Token expired. New token issued: {newToken}";
            }
            return "Login successful with token";
        }

        private bool IsTokenExpired(ClaimsPrincipal principal)
        {
            var expirationClaim = principal.Claims.FirstOrDefault(c => c.Type == "exp");
            if (expirationClaim != null && long.TryParse(expirationClaim.Value, out var expirationUnixTime))
            {
                var expirationDateTime = DateTimeOffset.FromUnixTimeSeconds(expirationUnixTime).UtcDateTime;
                return DateTime.UtcNow >= expirationDateTime;
            }
            return true;
        }
        public async Task<LoginResponse> LoginAsync(LoginModel request)
        {
            var user = await _context.Data_User_Apps
                .SingleOrDefaultAsync(u => u.personID == request.username);

            if (user == null)
            {
                return new LoginResponse { Success = false, Message = "User not found" };
            }

            string hashPassword = ComputeMd5Hash(request.password).ToUpper();

            if (user.passWord != hashPassword || user.factoryID != request.FactoryID)
            {
                return new LoginResponse { Success = false, Message = "Invalid password" };
            }

            var token = GenerateNewToken(user.personID);
            user.AccessToken = token;
            await _context.SaveChangesAsync();

            return new LoginResponse { Success = true, Message = "Login successful", Token = token };
        }
        public async Task<LoginResponse> LoginSignedAsync(LoginSignedModel request)
        {
            var user = await _context.Data_User_Apps
                .SingleOrDefaultAsync(u => u.personID == request.username);

            if (user == null)
            {
                return new LoginResponse { Success = false, Message = "User not found" };
            }

            string hashPassword = ComputeMd5Hash(request.password).ToUpper();

            if (user.passWord != hashPassword)
            {
                return new LoginResponse { Success = false, Message = "Invalid password" };
            }

            var token = GenerateNewToken(user.personID);
            user.AccessToken = token;
            await _context.SaveChangesAsync();

            return new LoginResponse { Success = true, Message = "Login successful", Token = token };
        }

        private string GenerateNewToken(string userId)
        {
            var claims = new[]
            {
        new Claim(ClaimTypes.Name, userId)
    };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.UtcNow.AddSeconds(20);

            var token = new JwtSecurityToken(
                issuer: "yourIssuer",
                audience: "yourAudience",
                claims: claims,
                expires: expiration,
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private ClaimsPrincipal ValidateJwtToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtToken && jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return principal;
                }
            }
            catch
            {
                // Token is invalid
            }

            return null;
        }
        public static string ComputeMd5Hash(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                var sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
        public async Task<string> UpdatePasswordAsync(string personID, string id, string idDay, string birthDay, string newPassword,string factoryID)
        {
            if (string.IsNullOrEmpty(personID) || string.IsNullOrEmpty(id) ||
                string.IsNullOrEmpty(idDay) || string.IsNullOrEmpty(birthDay) || string.IsNullOrEmpty(newPassword) || string.IsNullOrEmpty(factoryID))
            {
                return "Invalid input";
            }

            DateTime parsedIdDay;
            DateTime parsedBirthDay;

            if (!DateTime.TryParseExact(idDay, "dd/MM/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out parsedIdDay))
            {
                return "Invalid idDay";
            }

            if (!DateTime.TryParseExact(birthDay, "dd/MM/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out parsedBirthDay))
            {
                return "Invalid birthDay";
            }

            var hashPassword = ComputeMd5Hash(newPassword);
            var user = await _context.Data_User_Apps
                .SingleOrDefaultAsync(u => u.personID == personID &&
                                           u.id == id && u.idDay == parsedIdDay && u.birthDay == parsedBirthDay && u.factoryID == factoryID);
            if (user == null)
            {
                return "User not found or information does not match";
            }
            user.passWord = hashPassword.ToUpper();
            _context.Data_User_Apps.Update(user);
            await _context.SaveChangesAsync();

            return "Password updated successfully";
        }


    }
}
