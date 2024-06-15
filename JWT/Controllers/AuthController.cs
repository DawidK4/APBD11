using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JWT.Model;
using JWT.Services;

namespace GakkoHorizontalSlice.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            if (IsValidUser(loginModel.Username, loginModel.Password))
            {
                var token = GenerateJwtToken(loginModel.Username);
                var refreshToken = GenerateRefreshToken();

                await _userService.SaveRefreshTokenAsync(loginModel.Username, refreshToken);

                return Ok(new
                {
                    Token = token,
                    RefreshToken = refreshToken
                });
            }

            return Unauthorized("Invalid username or password");
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshModel refreshModel)
        {
            if (IsValidRefreshToken(refreshModel.RefreshToken, out var username))
            {
                var newToken = GenerateJwtToken(username);
                var newRefreshToken = GenerateRefreshToken();

                await _userService.SaveRefreshTokenAsync(username, newRefreshToken);

                return Ok(new
                {
                    Token = newToken,
                    RefreshToken = newRefreshToken
                });
            }

            return Unauthorized("Invalid refresh token");
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if (!await _userService.IsUsernameUniqueAsync(registerModel.Username))
            {
                return BadRequest("Username is already taken.");
            }

            var hashedPassword = HashPassword(registerModel.Password);
            await _userService.CreateUserAsync(registerModel.Username, hashedPassword);

            return Ok("User registered successfully.");
        }

        private bool IsValidUser(string username, string password)
        {
            var user = _userService.GetUserByUsernameAsync(username).Result;
            if (user == null)
            {
                return false;
            }

            return VerifyPassword(password, user.PasswordHash);
        }

        private bool IsValidRefreshToken(string refreshToken, out string username)
        {
            username = _userService.GetUsernameByRefreshTokenAsync(refreshToken).Result;
            return !string.IsNullOrEmpty(username);
        }

        private string GenerateJwtToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("your_secure_key_with_at_least_256_bits_or_more"); 

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        
        private byte[] GenerateJwtKey()
        {
            var key = new byte[16]; 
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }
        
        private string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes);
            }
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                var builder = new StringBuilder();
                foreach (var b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private bool VerifyPassword(string password, string hashedPassword)
        {
            var hashOfInput = HashPassword(password);
            return StringComparer.OrdinalIgnoreCase.Compare(hashOfInput, hashedPassword) == 0;
        }
    }
}

