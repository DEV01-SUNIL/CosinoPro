using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasinoPro.Models
{
    public class ProgConstants
    {
        public const string ApiToken = "ApiToken";



        #region headers
        public const string Authorization = "Authorization";
        public const string SessionLoggedInUser = "LoggedInUser";
        public const string SessionLoggedInCustomerUser = "LoggedInCustomerUser";
        public const string ErrMsg = "ErrMsg";
        //Admin Login Key/IV
        public const string Key = "Key";
        public const string IV = "IV";
        #endregion
    }
}
