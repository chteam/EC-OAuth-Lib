
using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Paipai;


namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="PaipaiAccountAuthenticationMiddleware"/>
    /// </summary>
    public static class PaipaiAccountAuthenticationExtensions
    {

        public static IAppBuilder UsePaipaiAccountAuthentication(this IAppBuilder app, PaipaiAccountAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(PaipaiAccountAuthenticationMiddleware), app, options);
            return app;
        }
        public static IAppBuilder UsePaipaiAccountAuthentication(
            this IAppBuilder app,
            string appKey,
            string secret)
        {
            return UsePaipaiAccountAuthentication(
                app,
                new PaipaiAccountAuthenticationOptions
                {
                    AppKey = appKey,
                    Secret = secret,
                });
        }
    }
}
