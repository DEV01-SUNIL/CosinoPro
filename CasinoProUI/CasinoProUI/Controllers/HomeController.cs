using CasinoProUI.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;
using System.Text;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;
using CasinoPro.Models;
using CasinoProUI.Services;
using System.Reflection;

namespace CasinoProUI.Controllers
{
    public class HomeController : DefaultController
    {
        public HomeController(IStaticService staticService, IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory, IConfiguration configuration) : base(staticService, httpContextAccessor, httpClientFactory, configuration, "Home")
        {
        }

        //[TypeFilter(typeof(Authorize))]
        public async Task<IActionResult> Index()
        {
            if (LoginAppUser == null)
            {
                return RedirectToAction("Index", "Login");
            }
            VMRegister vMRegister = new VMRegister();
            ViewBag.Page = "Start Of Fulfilment";
            ResJsonOutput result = await _staticService.PostDataAsync("/Admin/GetAdminDetails", vMRegister);
            if (result.Status.IsSuccess)
            {
                if (result.Data != null)
                {
                    vMRegister = CommonLib.ConvertJsonToObject<VMRegister>(result.Data);
                }
            }
            else
            {
                ViewBag.ErrMsg = result.Status.Message;
            }

            return View(vMRegister);
        }

    }
}
