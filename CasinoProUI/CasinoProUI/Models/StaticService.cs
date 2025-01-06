using CasinoPro.Models;
using CasinoProUI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;


namespace CasinoProUI.Services
{
    public class StaticService : IStaticService
    {
        private readonly SessionHelper _sessionHelper;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        public StaticService( SessionHelper sessionHelper, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
           _sessionHelper = sessionHelper;
            _httpContextAccessor = httpContextAccessor;
           _configuration = configuration;
        }

       

        public T GetSessionValue<T>(string key)
        {
            try
            {
                if (_httpContextAccessor.HttpContext != null)
                    return _httpContextAccessor.HttpContext.
                           Session.GetObject<T>(key);
                else
                    return default(T);
            }
            catch
            {
                return default(T);
            }
        }


        public void SetCustomerUserSessions(AppUserLoginData logindata)
        {
            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.ApiToken, logindata.AuthToken.Token);
            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.SessionLoggedInCustomerUser, logindata.cmsuser);
        }
        public void SetUserSessions(AppUserLoginData logindata)
        {
            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.ApiToken, logindata.AuthToken.Token);
            _httpContextAccessor.HttpContext.Session.SetObject(ProgConstants.SessionLoggedInUser, logindata.cmsuser);
        }

        public void SetLoginCookies(VMRegister logindata)
        {
            string coockieName = "Passport";
            CookieOptions option = new CookieOptions();
            option.Expires = DateTime.Now.AddDays(30);

            _httpContextAccessor.HttpContext.Response.Cookies.Append(coockieName, EncryptDecrypt.Encrypt(Newtonsoft.Json.JsonConvert.SerializeObject(logindata), _configuration["CookieConfigs:Key"], _configuration["CookieConfigs:IV"]), option);
        }

        public ResJsonOutput VerifyUser(VMLogin loginmodel)
        {
            ResJsonOutput result = new ResJsonOutput();
            if (loginmodel != null)
            {
                var req = PostDataAsync(APiURLs.Login, loginmodel);
                req.Wait();
                result = req.Result;
                if (result.Status.IsSuccess)
                {
                    if (result.Data != null)
                    {
                        AppUserLoginData logindata = CommonLib.ConvertJsonToObject<AppUserLoginData>(result.Data);
                        SetUserSessions(logindata);
                    }
                    else
                    {
                        
                    }
                }
            }
            return result;
        }

        public async Task<ResJsonOutput> PostDataAsync(string ApiPath, object obj, List<KeyValue> Headers = null)
        {

            string APIPath = _configuration["URLs:BaseUrl"];
            string LoginApiToken = GetSessionValue<string>(ProgConstants.ApiToken);
            if (Headers == null)
            {
                Headers = new List<KeyValue>() { new KeyValue(ProgConstants.Authorization, LoginApiToken) };
            }
            else
            {
                Headers.Add(new KeyValue(ProgConstants.Authorization, LoginApiToken));
            }
            try
            {
                return await RequestHandler.PostDataAsync<ResJsonOutput>(APIPath + ApiPath, obj, Headers);
            }
            catch (Exception ex)
            {
                ResJsonOutput result = new ResJsonOutput();
                result.Status.IsSuccess = false;
                result.Status.StatusCode = "GNLERR";
                result.Status.Message ="error";
                return result;
            }
        }
        public VMRegister GetLoginUser()
        {
            VMRegister cMSUser = GetSessionValue<VMRegister>(ProgConstants.SessionLoggedInUser);
            if (cMSUser == null)
            {
                string coockieName = "Passport";
                if (_httpContextAccessor.HttpContext.Request.Cookies[coockieName] != null)
                {
                    string cookieValueFromReq = EncryptDecrypt.Decrypt(_httpContextAccessor.HttpContext.Request.Cookies[coockieName].IsNullString(), _configuration["CookieConfigs:Key"], _configuration["CookieConfigs:IV"]);
                    VMLogin loginmodel = CommonLib.ConvertJsonToObject<VMLogin>(cookieValueFromReq);
                    if (loginmodel != null)
                    {
                        ResJsonOutput result = VerifyUser(loginmodel);
                        if (result.Status.IsSuccess == true)
                        {
                            //CMSUserLoginData logindata = CommonLib.ConvertJsonToObject<CMSUserLoginData>(result.Data);
                            //SetLoginCookies(loginmodel);
                        }
                        else
                        {
                            ClearSession().Wait();
                        }
                    }
                }
            }
            return cMSUser;
        }
        public async Task ClearSession()
        {
            string LoginApiToken = GetSessionValue<string>(ProgConstants.ApiToken);
            if (LoginApiToken.IsNullString() != "")
            {
                ResJsonOutput result = await PostDataAsync("/CMS/Login/Logout", null);
            }

            foreach (var cookie in _httpContextAccessor.HttpContext.Request.Cookies.Keys)
            {
                _httpContextAccessor.HttpContext.Response.Cookies.Delete(cookie);
            }
            _httpContextAccessor.HttpContext.Session.Clear();

            //_httpContextAccessor.HttpContext.Response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate");
            //_httpContextAccessor.HttpContext.Response.Headers.Add("Pragma", "no-cache");
            //_httpContextAccessor.HttpContext.Response.Headers.Add("Expires", "0");
        }




    }
}
