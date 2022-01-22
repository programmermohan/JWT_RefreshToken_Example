using JWT_RefreshToken_Example.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWT_RefreshToken_Example.Controllers
{
    [Route("api/[controller]")]
    [Consumes("application/json")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _Configarion;
        private readonly ApplicationDbContext _dbContext;
        public AuthenticationController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _Configarion = configuration;
            _dbContext = context;
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var UserExist = await _userManager.FindByNameAsync(model.UserName);
            if (UserExist != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Already Exists" });
            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = new Guid().ToString(),
                UserName = model.UserName
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });
            }

            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//

        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var UserExist = await _userManager.FindByNameAsync(model.UserName);
            if (UserExist != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Already Exists" });
            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = new Guid().ToString(),
                UserName = model.UserName
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });
            }

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }

            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var AuthClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    AuthClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = GenerateAccessToken(AuthClaims);
                var refreshToken = GenerateRefreshToken();

                //find user in refreshtoken table and update or add the respective values in refresh token table
                UpdateRefreshTokenDatabase(user.UserName, refreshToken);

                return Ok(new ResponseModel()
                {
                    access_token = token,
                    Refresh_token = refreshToken,
                    User = user.UserName
                });
            }

            return Unauthorized();
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//

        [HttpPost]
        [Route("Refresh")]
        public async Task<IActionResult> Refresh(TokenModel tokenModel)
        {
            string access_Token = tokenModel.access_token;
            string refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromTokenExpired(access_Token);

            var username = principal.Identity.Name;

            //validate user in dbcontext
            var user = await _userManager.FindByNameAsync(username);
            // validate the user by refresh token as well

            if (user == null)
            {
                return BadRequest("Invalid client request");
            }

            var newAccessToken = GenerateAccessToken(principal.Claims);
            var newRefreshToken = GenerateRefreshToken();

            //update the refresh token in db
            UpdateRefreshTokenDatabase(user.UserName, newRefreshToken);

            return Ok(new ResponseModel()
            {
                access_token = newAccessToken,
                Refresh_token = newRefreshToken,
                User = user.UserName
            });
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//
        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            try
            {
                var authSignKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_Configarion["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _Configarion["JWT:ValidIssuer"],
                    audience: _Configarion["JWT:ValidAudience"],
                    expires: DateTime.Now.AddSeconds(50),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSignKey, SecurityAlgorithms.HmacSha256)
                    );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                return tokenString;
            }
            catch (Exception)
            {
                throw;
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//
        public string GenerateRefreshToken()
        {
            try
            {
                var RandomNumber = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(RandomNumber);
                    return Convert.ToBase64String(RandomNumber);
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//
        public ClaimsPrincipal GetPrincipalFromTokenExpired(string Token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = _Configarion["JWT:ValidAudience"],
                    ValidIssuer = _Configarion["JWT:ValidIssuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_Configarion["JWT:Secret"])),
                    ValidateLifetime= false
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                SecurityToken securityToken;

                var principal = tokenHandler.ValidateToken(Token, tokenValidationParameters, out securityToken);
                var JwtSecurityToken = securityToken as JwtSecurityToken;
                if (JwtSecurityToken == null || !JwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    throw new SecurityTokenException("Invalid token");

                return principal;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//
        public void UpdateRefreshTokenDatabase(string UserName, string refreshToken)
        {
            try
            {
                RefreshToken _refreshToken = _dbContext.RefreshTokens.OrderByDescending(a => a.AddedDate)
                .FirstOrDefault(x => x.UserName == UserName);
                if (_refreshToken != null)
                {
                    _refreshToken.Reresh_token = refreshToken;
                    _refreshToken.AddedDate = DateTime.Now;
                    _refreshToken.ExpiryDate = DateTime.Now.AddDays(5);
                    _refreshToken.IsRevoked = false;
                    _dbContext.SaveChanges();
                }
                else
                {
                    _refreshToken = new RefreshToken()
                    {
                        UserName = UserName,
                        Reresh_token = refreshToken,
                        IsRevoked = false,
                        AddedDate = DateTime.Now,
                        ExpiryDate = DateTime.Now.AddDays(5),
                    };
                    _dbContext.RefreshTokens.Add(_refreshToken);
                    _dbContext.SaveChanges();
                }
            }
            catch (Exception)
            {

                throw;
            }
        }

        //-------------------------------------------------------------------------------------------------------------------------------------------------------//
    }
}
