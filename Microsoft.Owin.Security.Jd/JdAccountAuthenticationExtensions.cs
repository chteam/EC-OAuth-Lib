
using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jd;
 

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="JdAccountAuthenticationMiddleware"/>
    /// </summary>
    public static class JdAccountAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using jd.com Account
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseJingDongAccountAuthentication(this IAppBuilder app, JdAccountAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(JdAccountAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using jd.com Account
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appKey">The appkey of application in jd.com</param>
        /// <param name="secret">The secret of application in jd.com</param>
        /// <returns></returns>
        public static IAppBuilder UseJingDongAccountAuthentication(
            this IAppBuilder app,
            string appKey,
            string secret)
        {
            return UseJingDongAccountAuthentication(
                app,
                new JdAccountAuthenticationOptions
                {
                    AppKey = appKey,
                    Secret = secret,
                });
        }
    }
}
