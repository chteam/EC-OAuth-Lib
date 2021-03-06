﻿
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Paipai.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class PaipaiAccountReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// Initializes a new <see cref="PaipaiAccountReturnEndpointContext"/>.
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public PaipaiAccountReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
