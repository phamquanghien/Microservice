using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Data;
using AuthService.Models.Entities;
using AuthService.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SharedLibrary;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, RoleManager<IdentityRole> roleManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _roleManager = roleManager;
            _context = context;
        }
        [HttpGet("get-all-user")]
        [Authorize(Policy = nameof(SystemPermissions.GetAllUsers))]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.Select(user => new
            {
                user.Id,
                user.Email,
                Roles = _userManager.GetRolesAsync(user).Result
            }).ToListAsync();

            return Ok(users);
        }
        [Authorize(Policy = nameof(SystemPermissions.GetUserById))]
        [HttpGet("get-user-by-id/{userId}")]
        public async Task<IActionResult> GetUserById(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID is required.");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var userDto = new
            {
                user.Id,
                user.Email,
                Roles = _userManager.GetRolesAsync(user).Result
            };

            return Ok(userDto);
        }
        [Authorize(Policy = nameof(SystemPermissions.Register))]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterVM model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return Ok(new { Message = "User registered successfully" });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest(ModelState);
        }
        //Username: admin@gmail.com;
        //Password: Humg!@#456
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginVM model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email,
                        model.Password, model.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Email);
                    var token = await GenerateJsonWebToken(user);
                    var refreshToken = await GenerateRefreshToken(user.Id);
                    var cookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict,
                        Expires = refreshToken.ExpiredTime
                    };
                    Response.Cookies.Append("refreshToken", refreshToken.Token, cookieOptions);

                    return Ok(new { token = token, userName = user.UserName });
                }

                return Unauthorized();
            }
            return BadRequest(ModelState);
        }
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            Response.Cookies.Delete("refreshToken");
            return Ok(new { Message = "Logout successful" });
        }
        private async Task<string> GenerateJsonWebToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));
            foreach (var role in userRoles)
            {
                var roleClaims = await _roleManager.GetClaimsAsync(await _roleManager.FindByNameAsync(role));
                claims.AddRange(roleClaims.Where(c => c.Type == "Permission"));
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"], audience: _configuration["Jwt:Audience"], claims: claims,
            expires: DateTime.Now.AddMinutes(10), signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        [Authorize]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshTokenValue))
            {
                return BadRequest("Invalid client request");
            }

            var user = await _userManager.Users.Include(u => u.RefreshTokens)
                                               .FirstOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == refreshTokenValue));

            if (user == null || user.RefreshTokens.All(t => t.Token != refreshTokenValue || t.IsExpired || t.IsRevoked))
            {
                return Unauthorized();
            }

            var refreshToken = user.RefreshTokens.First(t => t.Token == refreshTokenValue);
            if (!refreshToken.IsActive)
            {
                return Unauthorized();
            }

            var newJwtToken = await GenerateJsonWebToken(user);
            var newRefreshToken = await GenerateRefreshToken(user.Id);

            refreshToken.Revoked = DateTime.UtcNow;
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                // Secure = true, //=> HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = newRefreshToken.ExpiredTime
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
            return Ok(new { token = newJwtToken });
        }
        private async Task<RefreshToken> GenerateRefreshToken(string userId)
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiredTime = DateTime.UtcNow.AddMinutes(2),
                UserId = userId
            };
            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
            return refreshToken;
        }
    }
}