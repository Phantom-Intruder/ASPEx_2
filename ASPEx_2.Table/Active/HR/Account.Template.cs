using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using ASPEx_2.Table.Utility.System;
using ASPEx_2.Table.Utility.System.Loggers;
using System.Web.Security;
using System.Security.Cryptography;

using Volume.Logger;

namespace ASPEx_2.Table.Active.HR
{
    public partial class Account : GenericPrincipal
    {
        #region These are used to make the project build - they are not needed

        public string Email;
        public int ID;
        public int Status;
        public string Password;
        public string Salt;
        public string ListText;

        #endregion

        #region This base constructor should be applied to the main Account class

        protected Account()
            : base(new GenericIdentity("Do not use"), null)
        {
            throw new InvalidOperationException("Do not use this constructor");
        }

        #endregion

#warning TODO: Code below should be copied over to the main Account class

        #region Enum

        /// <summary>
        /// Represents the level of an account.
        /// </summary>
        public enum Level
        {
            /// <summary>
            /// Default level for all accounts.
            /// </summary>
            All
        }

        #endregion

        #region Status Constants

        /// <summary>
        /// Account is active.
        /// </summary>
        public const int        STATUS_ACTIVE           = 1;

        /// <summary>
        /// Account is inactive.
        /// </summary>
		public const int        STATUS_INACTIVE         = 0;

        #endregion

        #region ExecuteCreate

        /// <summary>
        /// Gets an account by email address.
        /// </summary>
        /// <param name="email">Email address to get for.</param>
        /// <returns>Account</returns>
        public static Account ExecuteCreate(string email)
        {
            throw new NotImplementedException("Account class should be overwritten during framework generation");
        }

        #endregion

        #region DB Methods

        public void UpdatePassword(string NewPassword)
        {
            throw new NotImplementedException("Account class should be overwritten during framework generation");
        }

        #endregion

        #region Authentication

        /// <summary>
        /// Authenticates an account based on the specified credentials.
        /// </summary>
        /// <param name="Email">The email address of account to check.</param>
        /// <param name="Password">The password to check.</param>
        public static bool Authenticate(string Email, string Password)
        {
            bool                            result                      = false;

            // Get the account by email
            Account                         account                     = ExecuteCreate(Email);

            // Check it exists
            if (account != null)
            {
                // Get the password
                string                      encryptedPassword           = GetPassword(Password, account.Salt);

                // Check to see if the password given matches the password of the account
                if (encryptedPassword.ToLowerInvariant() == account.Password.ToLowerInvariant())
                {
                    // It does match
                    result                                              = true;
                }
                else
                {
                    /// Check against the master account
                    string                  masterPasswordUser          = Config.MasterAccount;

                    // Get the account
                    account                                             = ExecuteCreate(masterPasswordUser);

                    // Check exists
                    if (account != null)
                    {
                        // Get the password
                        encryptedPassword                               = GetPassword(Password, account.Salt);

                        // Check to see if the password given matches the password of the account
                        if (encryptedPassword.ToLower() == account.Password.ToLower())
                        {
                            result                                      = true;
                        }
                    }
                    else
                    {
                        /// The master account was not found!
                        Log.Info(string.Format("Account associated with the master password ({0}) was not found. The master password could not be checked for this authentication.", masterPasswordUser));
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Checks if the account has the specified level.
        /// </summary>
        /// <param name="RequiredLevel">Level to check for.</param>
        /// <returns>True if has the specified level, otherwise false.</returns>
        public bool HasLevel(Level RequiredLevel)
        {
            bool                    result                  = false;

            // Perform check
            if (RequiredLevel == Level.All)
            {
                // All users have this level
                result                                      = true;
            }

            return result;
        }

        /// <summary>
        /// Concatenates the salt and password before returning the encypted value.
        /// </summary>
        /// <param name="Password">Password to get from..</param>
        /// <param name="Salt">Salt to get from.</param>
        /// <returns></returns>
        protected static string GetPassword(string Password, string Salt)
        {
            return FormsAuthentication.HashPasswordForStoringInConfigFile(String.Concat(Password, Salt), "SHA1");
        }

        /// <summary>
        /// Generates a new random password, and updates the Account with it.
        /// </summary>	
        /// <returns>The newly generated password.</returns>
        public string GenerateAndUpdatePassword()
        {
            // Generate new
            string                      newPassword                 = GeneratePassword();

            // Update it
            this.UpdatePassword(newPassword);

            return newPassword;
        }

        /// <summary>
        /// Generates a new, randomised password.
        /// </summary>
        /// <returns>The newly generated password.</returns>
        protected static string GeneratePassword()
        {
            // Length to create
            int                             length                      = 6;

            // Get a random number generator provider
            RNGCryptoServiceProvider        crypt                       = new RNGCryptoServiceProvider();

            // Create byte array
            byte[]                          random                      = new byte[length];

            // Put into the provider
            crypt.GetBytes(random);

            // Get string to generate from
            string                          chars                       = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789";

            // Create string
            char[]                          password                    = new char[length];

            // Loop through
            for (int i = 0; i < length; i++)
            {
                // For each position in the password, get the modulus position from the characters,
                password[i]                                             = chars[(int)random[i] % chars.Length];
            }

            return new string(password);
        }

        /// <summary>
        /// Generates a salt for use when creating a salted hash password
        /// </summary>
        /// <returns></returns>
        protected static string GenerateSalt()
        {
            RNGCryptoServiceProvider            crypto                  = new RNGCryptoServiceProvider();
            byte[]                              buffer                  = new byte[16];

            crypto.GetBytes(buffer);

            return Convert.ToBase64String(buffer);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Gets the status string
        /// </summary>
        /// <param name="status"></param>
        /// <returns></returns>
        public static string GetStatusText(int status)
        {
            string  result          = "";

            switch (status)
            {
                case STATUS_ACTIVE:
                    result          = "Active";
                    break;
                case STATUS_INACTIVE:
                    result          = "Inactive";
                    break;
            }

            return result;
        }

        #endregion
    }
}
