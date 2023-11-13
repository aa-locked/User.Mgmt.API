using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace User.Mgmt.API.Controllers
{
    [Authorize(Roles =("IMS Admin"))]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [HttpGet("employees")]
        [Authorize( policy: "GetDataPolicy")]
        public IEnumerable<string> Get()
        {
            return new List<string>() { "Aalok", "Saru" };
        }
    }
}
