using JWT_RefreshToken_Example.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_RefreshToken_Example.Controllers
{
    [Authorize(Roles = UserRoles.Admin)]
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeesController : ControllerBase
    {
        [HttpGet]
        [Route("GetEmployees")]
        public List<string>GetEmployees()
        {
            return new List<string>() {"Employee01", "Employee02", "Employee03", "Employee04", "Employee05"};
        }
    }
}
