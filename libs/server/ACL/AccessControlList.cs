﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Garnet.server.ACL
{
    /// <summary>
    /// Models the high-level Access Control List (ACL) that defines access and command limitations for Garnet users.
    /// </summary>
    public class AccessControlList
    {
        /// <summary>
        /// Username to use for the default user
        /// </summary>
        const string DefaultUserName = "default";

        /// <summary>
        /// Arbitrary Key for new user lock object.
        /// </summary>
        const string NewUserLockObjectKey = "441a61e2-4d4e-498e-8ca0-715cf550e5be";

        /// <summary>
        /// Dictionary containing all users defined in the ACL
        /// </summary>
        ConcurrentDictionary<string, User> _users = new();

        /// <summary>
        /// Dictionary containing stable lock objects for each user in the ACL.
        /// </summary>
        ConcurrentDictionary<string, object> _userLockObjects = new();

        /// <summary>
        /// The currently configured default user (for fast default lookups)
        /// </summary>
        User _defaultUser;

        /// <summary>
        /// The <see cref="RespServerSession"/>s that will receive access control list change notifications.
        /// </summary>
        private readonly ConcurrentDictionary<string, RespServerSession> _subscribedSessions = new();

        /// <summary>
        /// Creates a new Access Control List from an optional ACL configuration file
        /// and sets the default user's password, if not provided by the configuration.
        /// </summary>
        /// <param name="defaultPassword">The password for the default user (if not provided by configuration file).</param>
        /// <param name="aclConfigurationFile">ACL configuration file.</param>
        /// <exception cref="ACLException">Thrown if configuration file cannot be parsed.</exception>
        public AccessControlList(string defaultPassword = "", string aclConfigurationFile = null)
        {
            if (!string.IsNullOrEmpty(aclConfigurationFile))
            {
                // Attempt to load ACL configuration file
                Load(defaultPassword, aclConfigurationFile);
            }
            else
            {
                // If no ACL file is defined, only create the default user
                _defaultUser = CreateDefaultUser(defaultPassword);
            }
            _userLockObjects[NewUserLockObjectKey] = new object();
        }

        /// <summary>
        /// Returns the user with the given name.
        /// </summary>
        /// <param name="username">Username of the user to retrieve.</param>
        /// <returns>Matching user object, or null if no user with the given name was found.</returns>
        public User GetUser(string username)
        {
            if (_users.TryGetValue(username, out var user))
            {
                return user;
            }
            return null;
        }

        /// <summary>
        /// Returns the lock object for the user with the given name. This allows user level locks, which should only be
        /// used for rare cases where modifications must be made to a user object, most notably ACL SETUSER.
        ///
        /// If modifications to a user are necessary the following pattern is suggested:
        ///
        /// 1. Obtain the lock object for the user using this method.
        /// 2. Immediately take a lock on the object.
        /// 3. Read the user from the <see cref="AccessControlList"/> and make a copy with the copy constructor.
        /// 4. Modify the copy of the user object.
        /// 5. Replace the user in the <see cref="AccessControlList"/> using the AddOrReplace(User user) method.
        ///
        /// Note: This pattern will make the critical section under lock single threaded across all sessions, use very
        /// sparingly.
        /// </summary>
        /// <param name="username">Username of the user to retrieve.</param>
        /// <returns>Matching user lock object.</returns>
        public object GetUserLockObject(string username)
        {
            if (_userLockObjects.TryGetValue(username, out var userLockObject))
            {
                return userLockObject;
            }

            return _userLockObjects[NewUserLockObjectKey];
        }

        /// <summary>
        /// Returns the currently configured default user.
        /// </summary>
        /// <returns>The default user of this access control list.</returns>
        public User GetDefaultUser()
        {
            return _defaultUser;
        }

        /// <summary>
        /// Adds or replaces the given user in the ACL.
        /// </summary>
        /// <param name="user">User to add or replaces in the list.</param>
        public void AddOrReplaceUser(User user)
        {
            // If a user with the given name already exists replace the user, otherwise add the new user.
            _users[user.Name] = user;
            _ = _userLockObjects.TryAdd(user.Name, new object());
            this.NotifySubscribers(user);
        }

        /// <summary>
        /// Deletes the user associated with the given username.
        /// </summary>
        /// <param name="username">Username of the user to delete.</param>
        /// <returns>true if successful, false if no matching user was found.</returns>
        /// <exception cref="ACLException">Thrown if the given user exists but cannot be deleted.</exception>
        public bool DeleteUser(string username)
        {
            if (username == DefaultUserName)
            {
                throw new ACLException("The special 'default' user cannot be removed from the system");
            }

            bool userDeleted = _users.TryRemove(username, out _);

            if (userDeleted)
            {
                _userLockObjects.TryRemove(username, out _);
            }

            return userDeleted;
        }

        /// <summary>
        /// Remove all users from the list.
        /// </summary>
        public void ClearUsers()
        {
            _users.Clear();
        }

        /// <summary>
        /// Return a list of all usernames and user objects.
        /// </summary>
        /// <returns>Dictionary of username/user pairs.</returns>
        public IReadOnlyDictionary<string, User> GetUsers()
        {
            return _users;
        }

        /// <summary>
        /// Creates the default user, if it does not exist yet.
        /// </summary>
        /// <param name="defaultPassword">Password to use if new user is created.</param>
        /// <returns>The newly created or already existing default user.</returns>
        User CreateDefaultUser(string defaultPassword = "")
        {
            User defaultUser;

            while (!_users.TryGetValue(DefaultUserName, out defaultUser))
            {
                // Default user always has full access
                defaultUser = new User(DefaultUserName);
                defaultUser.AddCategory(RespAclCategories.All);

                // Automatically created default users are always enabled
                defaultUser.IsEnabled = true;

                // Set the password if requested
                if (!string.IsNullOrEmpty(defaultPassword))
                {
                    ACLPassword password = ACLPassword.ACLPasswordFromString(defaultPassword);
                    defaultUser.AddPasswordHash(password);
                }
                else
                {
                    defaultUser.IsPasswordless = true;
                }

                // Add the user to the user list
                try
                {
                    AddOrReplaceUser(defaultUser);
                    break;
                }
                catch (ACLUserAlreadyExistsException)
                {
                    // If AddUser failed, continue looping to retrieve the concurrently created user
                }
            }
            return defaultUser;
        }

        /// <summary>
        /// Loads the given ACL configuration file and replaces all currently defined rules in this ACL.
        /// If the given ACL file contains errors, the old rules remain unmodified.
        /// </summary>
        /// <param name="defaultPassword">The password for the default user (if not defined in ACL configuration file)</param>
        /// <param name="aclConfigurationFile">ACL configuration file.</param>
        /// <exception cref="ACLException">Thrown if configuration file cannot be parsed.</exception>
        public void Load(string defaultPassword, string aclConfigurationFile)
        {
            // Attempt to load ACL configuration file
            if (!File.Exists(aclConfigurationFile))
            {
                throw new ACLException($"Cannot find ACL configuration file '{aclConfigurationFile}'");
            }

            // Import file into a new temporary access control list to guarantee atomicity
            AccessControlList acl = new();
            StreamReader streamReader;

            try
            {
                streamReader = new StreamReader(File.OpenRead(aclConfigurationFile), Encoding.UTF8, true);
            }
            catch
            {
                throw new ACLException($"Unable to open ACL configuration file '{aclConfigurationFile}'");
            }

            // Remove default user and load statements
            try
            {
                acl._users.Clear();
                acl.Import(streamReader, aclConfigurationFile);
            }
            catch (ACLParsingException exception)
            {
                throw new ACLException($"Unable to parse ACL rule {exception.Filename}:{exception.Line}:  {exception.Message}");
            }
            finally
            {
                streamReader.Close();
            }

            // Add back default user and update the cached default user handle
            _defaultUser = acl.CreateDefaultUser(defaultPassword);

            // Atomically replace the user list
            _users = acl._users;
        }

        /// <summary>
        /// Save current
        /// </summary>
        /// <param name="aclConfigurationFile"></param>
        public void Save(string aclConfigurationFile)
        {
            if (string.IsNullOrEmpty(aclConfigurationFile))
            {
                throw new ACLException($"ACL configuration file not set.");
            }

            // Lock to ensure one flush at a time
            lock (this)
            {
                StreamWriter streamWriter = null;
                try
                {
                    // Initialize so as to allow the streamwriter buffer to fill in memory and do a manual flush afterwards
                    streamWriter = new StreamWriter(path: aclConfigurationFile, append: false, encoding: Encoding.UTF8, bufferSize: 1 << 16)
                    {
                        AutoFlush = false
                    };

                    // Write lines into buffer
                    foreach (var user in _users)
                        streamWriter.WriteLine(user.Value.DescribeUser());

                    // Flush data buffer
                    streamWriter.Flush();
                }
                finally
                {
                    // Finally ensure streamWriter is closed
                    streamWriter?.Close();
                }
            }
        }

        /// <summary>
        /// Imports Access Control List rules from the given reader.
        /// </summary>
        /// <param name="input">Input text reader to a list of ACL user definition rules.</param>
        /// <param name="configurationFile">Configuration file identifier for clean debug messages.</param>
        /// <exception cref="ACLParsingException">Thrown if ACL rules cannot be parsed.</exception>
        void Import(StreamReader input, string configurationFile = "<undefined>")
        {
            // Read and parse input line-by-line
            string line;
            int curLine = 0;
            while ((line = input.ReadLine()) != null)
            {
                curLine++;

                // Skip empty lines and comments
                line = line.Trim();
                if (line.Length < 1 || line.StartsWith('#'))
                {
                    continue;
                }

                // Parse the ACL rules stored in the line
                try
                {
                    ACLParser.ParseACLRule(line, this);
                }
                catch (ACLException exception)
                {
                    throw new ACLParsingException(exception.Message, configurationFile, curLine);
                }
            }
        }

        /// <summary>
        /// Registers a <see cref="RespServerSession"/> to receive notifications when modifications are performed to the <see cref="AccessControlList"/>.
        /// </summary>
        /// <param name="respSession">The <see cref="RespServerSession"/> to register.</param>
        internal void Subscribe(RespServerSession respSession)
        {
            _subscribedSessions[respSession.AclSubscriberKey] = respSession;
        }

        /// <summary>
        /// Unregisters a <see cref="RespServerSession"/> to receive notifications when modifications are performed to the <see cref="AccessControlList"/>.
        /// </summary>
        /// <param name="respSession">The <see cref="RespServerSession"/> to register.</param>
        internal void Unsubscribe(RespServerSession respSession)
        {
            _ = _subscribedSessions.TryRemove(respSession.AclSubscriberKey, out _);
        }


        /// <summary>
        /// Notify the registered <see cref="RespServerSession"/> when modifications are performed to the <see cref="AccessControlList"/>.
        /// </summary>
        /// <param name="user">The created or updated <see cref="User"/> that triggered the notification.</param>
        private void NotifySubscribers(User user)
        {
            foreach (RespServerSession respSession in _subscribedSessions.Values)
            {
                respSession.NotifyAclChange(user);
            }
        }
    }
}