using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace CasinoPro.Models
{
    public class AppUserLoginData
    {
        public VMRegister cmsuser { get; set; }

        public TokenData AuthToken { get; set; }
    }
   

}
