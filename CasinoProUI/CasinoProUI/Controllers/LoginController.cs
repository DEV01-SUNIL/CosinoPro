using CasinoPro.Models;
using CasinoProUI.Models;
using CasinoProUI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace CasinoProUI.Controllers
{
    public class LoginController : DefaultController
    {

        public LoginController(IStaticService staticService, IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory, IConfiguration configuration) : base(staticService, httpContextAccessor,httpClientFactory, configuration, "Login")
        {
        }
        
        public IActionResult Index()
        {
            if (LoginAppUser != null)
            {
                return RedirectToAction("Index", "Home");
            }
            VMLogin model = new VMLogin();

            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.Key, CommonLib.generateRandomString());
            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.IV, CommonLib.generateRandomString());
            return View(model);
            
        }
        //[HttpPost]
        //public async Task<IActionResult> Index(VMLogin loginModel)
        //{

        //    if (ModelState.IsValid)
        //    {
        //        ResJsonOutput result = _staticService.VerifyUser(loginModel);
        //        if (result.Status.IsSuccess)
        //        {
        //            if (result.Data != null)
        //            {
        //                AppUserLoginData logindata = CommonLib.ConvertJsonToObject<AppUserLoginData>(result.Data);
        //                return RedirectToAction("Index", "Home");
        //            }
        //        }
        //        else
        //        {
        //            ViewBag.ErrMsg = result.Status.Message;
        //        }
        //    }
        //    return View(loginModel);

        //}
        [HttpPost]
        [ValidateAntiForgeryToken]
        //[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
        public async Task<IActionResult> Index(VMLogin loginModel)
        {
            string key, IV, plainText;
            try
            {
                key = _httpContextAccessor.HttpContext.Session.GetObject<string>(ProgConstants.Key).IsNullString();

                IV = _httpContextAccessor.HttpContext.Session.GetObject<string>(ProgConstants.IV).IsNullString();
                plainText = loginModel.Password;
            }
            catch (Exception ex)
            {
                return RedirectToAction("Index");
            }
            if (LoginAppUser != null)
            {
                return RedirectToAction("Index", "Home");
            }
            if (ModelState.IsValid)
            {
                ResJsonOutput result = _staticService.VerifyUser(loginModel);
                if (result.Status.IsSuccess)
                {
                    if (result.Data != null)
                    {
                        _httpContextAccessor.HttpContext.Session.Remove(ProgConstants.Key);
                        _httpContextAccessor.HttpContext.Session.Remove(ProgConstants.IV);
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.Key, CommonLib.generateRandomString());
                    _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.IV, CommonLib.generateRandomString());
                    ViewBag.ErrMsg = result.Status.Message;
                }
            }
            return View(loginModel);
        }
        private async Task<string> CallSecuredApi(string token)
        {
            string baseurl = _configuration["URLs:BaseUrl"];
            string securedApiUrl = baseurl + APiURLs.Verifitoken;
            // Create an HTTP request with the JWT token in the Authorization header
            var request = new HttpRequestMessage(HttpMethod.Get, securedApiUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Send the request to the secured API
            var response = await _httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                // Read the content of the response (the protected data)
                var result = await response.Content.ReadAsStringAsync();
                return result;
            }

            return "Access Denied or API Error";
        }
    }
}
