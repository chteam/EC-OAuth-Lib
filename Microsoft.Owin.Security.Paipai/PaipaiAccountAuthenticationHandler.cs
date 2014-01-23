using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Paipai.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Paipai
{
    internal class PaipaiAccountAuthenticationHandler : AuthenticationHandler<PaipaiAccountAuthenticationOptions>
    {
        private readonly ILogger _logger;

        public PaipaiAccountAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string access_token = null;
                string useruin = null;
                string appKey = null;
                string sign = null;
                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("access_token");
                if (values != null && values.Count == 1)
                {
                    access_token = values[0];
                }
                values = query.GetValues("useruin");
                if (values != null && values.Count == 1)
                {
                    useruin = values[0];
                }
                values = query.GetValues("app_oauth_id");
                if (values != null && values.Count == 1)
                {
                    appKey = values[0];
                }
                values = query.GetValues("sign");
                if (values != null && values.Count == 1)
                {
                    sign = values[0];
                }
                properties = new AuthenticationProperties() {RedirectUri = Options.DefaultCallBack};
                if (appKey != Options.AppKey)
                {
                    return null;
                }
                //todo:验证sign
                var context = new PaipaiAccountAuthenticatedContext(Context, access_token, useruin);

                context.Identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String,
                            Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.Name, ClaimValueTypes.String, Options.AuthenticationType),
                        new Claim("pp:UserUin", context.Id, ClaimValueTypes.String, Options.AuthenticationType),
                        new Claim("pp:AccessToken", context.AccessToken, ClaimValueTypes.String,
                            Options.AuthenticationType)
                    },
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);


                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteWarning("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                Response.Write("当前Provider 不支持 client-side 登录。");
                Response.StatusCode = 500;
            }

            return Task.FromResult<object>(null);
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await AuthenticateAsync();
            if (model == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                //Response.Redirect(Options.DefaultCallBack);
                Response.StatusCode = 500;
                return true;
            }

            var context = new PaipaiAccountReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }
    }
}