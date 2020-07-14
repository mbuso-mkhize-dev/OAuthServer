using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OAuthServer.ApplicationLogic.Entities;
using OAuthServer.ApplicationLogic.Interfaces;
using OAuthServer.Models;
using System.Threading.Tasks;

namespace OAuthServer.Controllers
{
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        public IActionResult Get()
        {
            return Ok();

        }
        // GET: User

        // POST: User/Create
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] UserModel model)
        {
            try
            {
                var response = await _userService.RegisterUserAsync(new UserEntity { Name = model.Name, Email = model.Email, Password = model.Password });
                return Ok(response);
            }
            catch
            {
                
            }

            return Ok();
        }

        // GET: User/Edit/5
      
    }
}