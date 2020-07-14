using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthServer.ApplicationLogic.Entities;
using OAuthServer.ApplicationLogic.Interfaces;
using OAuthServer.Models;
using System;
using System.Threading.Tasks;

namespace OAuthServer.Controllers
{
    [Route("[controller]")]
    public class OAuthController : Controller
    {
        private readonly IOAuthenticationService _oauthenticationService;
        public OAuthController(IOAuthenticationService oauthenticationService)
        {
            _oauthenticationService = oauthenticationService;
        }

        [Authorize(AuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme)]
        [AllowAnonymous]
        [HttpGet("me")]
        public ActionResult UserDetails()
        {
            return Ok();
        }

        [HttpPost("token")]
        public async Task<IActionResult> Authenticate([FromBody] UserModel userModel)
        {
            try
            {
                var response = await _oauthenticationService.AuthenticateUserAsync(new UserEntity { Email = userModel.Email, Password = userModel.Password });
                if(response != null)
                {
                    return Ok(response);
                }
                else
                {
                    return BadRequest();
                }
                
            }
            catch
            {
                return BadRequest();
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] OAuthModel model)
        {
            try
            {
                // TODO: Add insert logic here
                var response = await _oauthenticationService.AuthenticateUserFromRefreshToken(model.RefreshToken);
                return Ok(response);
            }
            catch
            {
                return BadRequest();
            }
        }
    }
}