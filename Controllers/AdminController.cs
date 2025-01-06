using CasinoPro.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CasinoPro.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AdminController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost("GetAdminDetails")]
        public async Task<ResJsonOutput> GetAdminDetails(VMLogin model)
        {
            ResJsonOutput resJsonOutput = new ResJsonOutput();
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null) { 
            resJsonOutput.Data = user;
            resJsonOutput.Status.IsSuccess = true;
            resJsonOutput.Status.StatusCode = "SUCCESS";
            resJsonOutput.Status.Message = "Founds.";

            }
            else
            {
                resJsonOutput.Status.IsSuccess = false;
                resJsonOutput.Status.StatusCode = "FAILIER";
                resJsonOutput.Status.Message = "User not registered!";
            }
            return resJsonOutput;
}
    }
}
