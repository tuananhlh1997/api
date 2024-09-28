using API_lvl_app.Models;
using Microsoft.AspNetCore.Mvc;

namespace API_lvl_app.Controllers
{
    public class AuthController : Controller
    {
        private readonly AuthService _accountService;

        public AuthController(AuthService accountService)
        {
            _accountService = accountService;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel request)
        {
            var result = await _accountService.LoginAsync(request);

            if (result is LoginResponse loginResponse && loginResponse.Success)
            {
                return Ok(new { Message = loginResponse.Message, Token = loginResponse.Token });
            }

            return Unauthorized(new { Message = result });
        }
        [HttpPost("loginsigned")]
        public async Task<IActionResult> LoginSigned([FromBody] LoginSignedModel request)
        {
            var result = await _accountService.LoginSignedAsync(request);

            if (result is LoginResponse loginResponse && loginResponse.Success)
            {
                return Ok(new { Message = loginResponse.Message, Token = loginResponse.Token });
            }

            return Unauthorized(new { Message = result });
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Token cannot be empty.");
            }

            var result = await _accountService.AuthenticateWithTokenAsync(token);

            if (result.StartsWith("Token expired") || result.StartsWith("Login successful"))
            {
                return Ok(result);
            }

            return Unauthorized(result);
        }
        [HttpPost("update-password")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordModel model)
        {
            if (model.IDDay == null || model.BirthDay == null)
            {
                return BadRequest("Date fields cannot be null");
            }

            var result = await _accountService.UpdatePasswordAsync(
                model.PersonID,
                model.ID,
                model.IDDay,
                model.BirthDay,
                model.NewPassword,
                model.FactoryID
            );

            if (result == "Invalid input")
            {
                return BadRequest(result);
            }
            if (result == "User not found or information does not match")
            {
                return NotFound(result);
            }

            return Ok(new { Message = result });
        }
    }
}
