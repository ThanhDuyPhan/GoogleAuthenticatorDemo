using Google.Authenticator;
using GoogleAuthenticatorDemo.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text;

namespace GoogleAuthenticatorDemo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        public ActionResult Login(LoginModel login)
        {
            bool status = false;
            var session = HttpContext.Session;

            if (session.GetString("Username") == string.Empty
                || session.GetString("IsValidTwoFactorAuthentication") == null
                || session.GetString("IsValidTwoFactorAuthentication") != "true")
            {
                string googleAuthKey = "P0W48S53";
                string UserUniqueKey = (login.UserName + googleAuthKey);

                //Take UserName And Password As Static - Admin As User And 456789 As Password
                if (login.UserName == "Admin" && login.Password == "0")
                {
                    session.SetString("UserName", login.UserName);

                    //Two Factor Authentication Setup
                    TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
                    var setupInfo = TwoFacAuth.GenerateSetupCode("MakeByMe.com", login.UserName, ConvertSecretToBytes(UserUniqueKey, false), 300);
                    session.SetString("UserUniqueKey", UserUniqueKey);
                    ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                    ViewBag.SetupCode = setupInfo.ManualEntryKey;
                    status = true;
                }
            }
            else
            {
                return RedirectToAction("Index");
            }
            ViewBag.Status = status;
            return View();
        }


        public ActionResult TwoFactorAuthenticate()
        {
            var token = Request.Form["CodeDigit"];
            var session = HttpContext.Session;
            TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
            string UserUniqueKey = session.GetString("UserUniqueKey");
            bool isValid = TwoFacAuth.ValidateTwoFactorPIN(UserUniqueKey, token, false);
            if (isValid)
            {
                string UserCode = Convert.ToBase64String(Encoding.UTF8.GetBytes(UserUniqueKey));

                session.SetString("IsValidTwoFactorAuthentication", "true");
                return RedirectToAction("Index");
            }

            ViewBag.Message = "Google Two Factor PIN is expired or wrong";
            return RedirectToAction("Login");
        }

        public ActionResult Login()
        {
            HttpContext.Session.SetString("UserName", string.Empty);
            HttpContext.Session.SetString("IsValidTwoFactorAuthentication", "false");
            return View();
        }

        public ActionResult Logoff()
        {
            HttpContext.Session.SetString("UserName", string.Empty);
            HttpContext.Session.SetString("IsValidTwoFactorAuthentication", "false");
            return RedirectToAction("Login");
        }

        public IActionResult Index()
        {
            var session = HttpContext.Session;
            if (session.GetString("Username") == string.Empty
                || session.GetString("IsValidTwoFactorAuthentication") == null
                || session.GetString("IsValidTwoFactorAuthentication") != "true")
            {
                return RedirectToAction("Login");
            }
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private byte[] ConvertSecretToBytes(string secret, bool secretIsBase32) =>
           secretIsBase32 ? Base32Encoding.ToBytes(secret) : Encoding.UTF8.GetBytes(secret);
    }
}
