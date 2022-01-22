using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_RefreshToken_Example.Authentication
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string UserName { get; set; }

        public string Reresh_token { get; set; }

        public bool IsRevoked { get; set; }

        public DateTime AddedDate { get; set; }

        public DateTime ExpiryDate { get; set; }
    }
}
