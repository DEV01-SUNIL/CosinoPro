using CasinoPro.Models;
using CasinoProUI.Models;
using CasinoProUI.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
namespace CasinoProUI.Controllers
{
    [Produces("application/json")]
    //[Route("MB/Default")]
    public class DefaultController : Controller
    {
        protected string LoginApiToken;
        protected long LoginAppUserId = 0;
        protected VMRegister LoginAppUser;
        protected DateTime Dt;
        protected long LoginPolicyUserId = 0;
        protected readonly IStaticService _staticService;
        protected IHttpContextAccessor _httpContextAccessor;
        protected readonly string _PageModelName;
        protected readonly HttpClient _httpClient;
        protected readonly IConfiguration _configuration;

        public DefaultController(IStaticService staticService, IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory, IConfiguration configuration, string PageModelName)
        {
            _staticService = staticService;
            _httpContextAccessor = httpContextAccessor;
            _PageModelName = PageModelName;
            _httpClient= httpClientFactory.CreateClient();
            _configuration= configuration;
            Dt = DateTime.Now;
            LoginAppUser = _staticService.GetLoginUser();
            if (LoginAppUser != null)
            {
                LoginAppUserId = 1;
            }
           

            LoginApiToken = staticService.GetSessionValue<string>(ProgConstants.ApiToken);
        }

        protected void CatchError(Exception ex)
        {
            string ControllerName = this.RouteData.Values["controller"].ToString();
            string ActionName = this.RouteData.Values["action"].ToString();
            string URL = this.HttpContext.Request.Path;
            string IPAddress = this.HttpContext.Connection.RemoteIpAddress.ToString();
            string Method = this.HttpContext.Request.Method;

            //ErrorLog errorLog = new ErrorLog();
            //errorLog.ControllerName = ControllerName;
            //errorLog.ActionName = ActionName;
            //errorLog.URL = URL;
            //errorLog.IPAddress = IPAddress;
            //errorLog.Method = Method;
            //errorLog.UserID = 0;

            //_staticService.LogError(errorLog, ex, _staticService);
        }
        protected async Task<object> FillDropDowns<T>(string ApiPath, object obj)
        {
            ResJsonOutput result = await _staticService.PostDataAsync(ApiPath, obj);
            if (result.Status.IsSuccess)
            {
                return CommonLib.ConvertJsonToObject<T>(result.Data);
            }
            else
            {
                return default(T);
            }
        }

        protected string GetModelStateErrors(ModelStateDictionary ModelState)
        {
            //result.Status.Message = await GetStatusMessage(result.Status.StatusCode);
            return string.Join("<br />", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)); ;
        }

       
        protected async Task<T> GetDetails<T>(object requestById, string path)
        {
            ResJsonOutput result = await _staticService.PostDataAsync(path, requestById);
            if (result.Status.IsSuccess)
            {
                if (result.Data != null)
                {
                    T model = CommonLib.ConvertJsonToObject<T>(result.Data);
                    return model;
                }
            }
            else
            {
                HttpContext.Session.SetObject(ProgConstants.ErrMsg, result.Status.Message);
            }
            return default(T);
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            ViewBag.PageModelName = _PageModelName;
            //ViewBag.LoginCMSUser = _staticService.GetLoginUser();
            //ViewBag.SidebarList = _staticService.GetSidebarList();
            //ViewBag.DllVersion = MyHelpers.GetAssemblyVersion();
            return;
        }

       

    }
}