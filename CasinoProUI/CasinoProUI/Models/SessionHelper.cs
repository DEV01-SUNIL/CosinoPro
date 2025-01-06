using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CasinoProUI.Services
{
    public class SessionHelper
    {

        private IHttpContextAccessor httpContextAccessor;

        public SessionHelper(IHttpContextAccessor obj)
        {
            this.httpContextAccessor = obj;
        }

        public T GetSessionValue<T>(string key)
        {
            try
            {
                if (httpContextAccessor.HttpContext != null)
                    return httpContextAccessor.HttpContext.
                           Session.GetObject<T>(key);
                else
                    return default(T);
            }
            catch
            {
                return default(T);
            }
        }
    }
}
