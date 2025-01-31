// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

namespace Garnet.server.ACL
{
    /// <summary>
    /// An interface for types that subscribe to <see cref="AccessControlList"/> changes.
    /// </summary>
    internal interface IAccessControlListSubscriber
    {
        /// <summary>
        /// A key for the subscriber.
        /// </summary>
        public string SubscriberKey { get; }

        /// <summary>
        /// Handle notification received when changes to the <see cref="AccessControlList"/> changes.
        /// </summary>
        /// <param name="user">The modified <see cref="User"/>.</param>
        public void Notify(User user);
    }
}
