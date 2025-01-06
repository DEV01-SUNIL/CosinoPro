using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasinoPro.Models
{
    public class ResStatus
    {
        [DefaultValue(false)]
        public bool IsSuccess { get; set; }
        public string Message { get; set; }

        //[DefaultValue("")]
        public string StatusCode { get; set; }
    }

    public class ResJsonOutput
    {
        public ResJsonOutput()
        {
            //Header = new Header();
            Data = new object();
            Status = new ResStatus();
        }
        //public Header Header { get; set; }
        public object Data { get; set; }
        public ResStatus Status { get; set; }
    }


    public class ResJsonOutputList
    {
        public ResJsonOutputList()
        {
            Data = new List<ResJsonOutput>();
        }

        public List<ResJsonOutput> Data { get; set; }
    }

}
