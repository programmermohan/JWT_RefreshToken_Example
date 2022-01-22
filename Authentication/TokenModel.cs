using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_RefreshToken_Example.Authentication
{
    public class TokenModel
    {
        public string access_token { get; set; }

        public string RefreshToken { get; set; }
    }
}
