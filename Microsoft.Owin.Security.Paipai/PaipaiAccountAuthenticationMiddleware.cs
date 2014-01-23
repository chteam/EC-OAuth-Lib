using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Paipai.Provider;
using Owin;

namespace Microsoft.Owin.Security.Paipai
{
    public class PaipaiAccountAuthenticationMiddleware : AuthenticationMiddleware<PaipaiAccountAuthenticationOptions>
    {

        private readonly ILogger _logger;
    

        /// <summary>
        /// Initializes a <see cref="PaipaiAccountAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public PaipaiAccountAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            PaipaiAccountAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.AppKey))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppKey"));
            }
            if (string.IsNullOrWhiteSpace(Options.Secret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "Secret"));
            }

            _logger = app.CreateLogger<PaipaiAccountAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new PaipaiAccountAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                    typeof(PaipaiAccountAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }


        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="PaipaiAccountAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<PaipaiAccountAuthenticationOptions> CreateHandler()
        {
            return new PaipaiAccountAuthenticationHandler(_logger);
        }
    }
}
