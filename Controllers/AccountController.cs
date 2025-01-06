using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CasinoPro.Models;

namespace CasinoPro.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ResJsonOutput> Register([FromBody] Register model)
        {
            ResJsonOutput resJsonOutput = new ResJsonOutput();
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                //await _userManager.AddToRoleAsync(user, "User");
                resJsonOutput.Status.IsSuccess=true;
                resJsonOutput.Status.StatusCode = "SUCCESS";
                resJsonOutput.Status.Message = "User registered susseccfully"; 
                
            }
            else
            {
                resJsonOutput.Status.IsSuccess = false;
                resJsonOutput.Status.StatusCode = "FAILIER";
                resJsonOutput.Status.Message = "User not registered!";
            }
            return resJsonOutput;
        }

        [HttpPost("login")]
        public async Task<ResJsonOutput> Login([FromBody] Login model)
        {
            ResJsonOutput resJsonOutput = new ResJsonOutput();
            AppUserLoginData appUserLoginData = new AppUserLoginData();
            VMRegister vMRegister = new VMRegister();
            TokenData tokenData=new TokenData();    
           var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                vMRegister.Username = model.Username;
                vMRegister.Password = model.Password;
                var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                    SecurityAlgorithms.HmacSha256));
                tokenData.Token = new JwtSecurityTokenHandler().WriteToken(token).ToString();
                tokenData.Expiry= long.Parse(_configuration["Jwt:ExpiryMinutes"]!);
                appUserLoginData.AuthToken= tokenData;  
                appUserLoginData.cmsuser = vMRegister;
                resJsonOutput.Data = appUserLoginData;
                resJsonOutput.Status.IsSuccess = true;
                resJsonOutput.Status.StatusCode = "SUCCESS";
                resJsonOutput.Status.Message = "User Login susseccfully";
               
               

            }
            else
            {
                resJsonOutput.Status.IsSuccess = false;
                resJsonOutput.Status.StatusCode = "FAILIER";
                resJsonOutput.Status.Message = "User not registered!";
            }

            return resJsonOutput;
        }

        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new { message = "Role added successfully" });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest("Role already exists");
        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("protected-data")]
        [Authorize]
        public IActionResult GetProtectedData()
        {
            var userName = User.Identity.Name;  // Access the username from the JWT
            return Ok(new
            {
                Message = "Access granted",
                UserName = userName
            });
        }
    }
}
