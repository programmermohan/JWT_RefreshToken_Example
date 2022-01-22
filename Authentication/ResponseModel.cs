using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_RefreshToken_Example.Authentication
{
    public class ResponseModel
    {
        public string access_token { get; set; }
        public string User { get; set; }
        public string Refresh_token { get; set; }
    }
}
