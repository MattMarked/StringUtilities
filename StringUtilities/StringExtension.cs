using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace StringUtilities
{
    
    public static class StringExtension 
    {
        /// <summary>
        /// Remove all leading and trailing white spaces and convert multiple white spaces to one single white space inside this string instance.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string TrimAndReduce(this string value)
        {
            return ConvertWhiteSpacesToSingleSpace(value).Trim();
        }

        /// <summary>
        /// Convert multiple white spaces to one single white space inside this string instance.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ConvertWhiteSpacesToSingleSpace(this string value)
        {
            return Regex.Replace(value, @"\s+", " ");
        }

        /// <summary>
        /// Determines whether the end of this string instance matches at least one string in the specified string array.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="values">The string array to compare to the substring at the end of this instance.</param>
        /// <returns>True if at least one value matches the end of this instance; otherwise, false.</returns>
        public static bool EndsWith(this string value, string[] values)
        {
            for(int i = 0; i < values.Length; i++)
            {
                if (value.EndsWith(values[i]))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Determines whether the beginning of this string instance matches at least one string in the specified string array.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="values">The string array to compare to the substring at the beginning of this instance.</param>
        /// <returns>True if at least one value matches the beginning of this instance; otherwise, false.</returns>
        public static bool StartsWith(this string value, string[] values)
        {
            for (int i = 0; i < values.Length; i++)
            {
                if (value.StartsWith(values[i]))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Determines if at least one value from the specified string array occurs as a substring within this string.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="values">The string array to seek.</param>
        /// <returns>True if at least one value occurs within this string; otherwise, false.</returns>
        public static bool Contains(this string value, string[] values)
        {
            for (int i = 0; i < values.Length; i++)
            {
                if (value.Contains(values[i]))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Returns characters from right of specified length
        /// </summary>
        /// <param name="value"></param>
        /// <param name="length">Max number of characters to return</param>
        /// <returns>Returns the last "lenght" characters from this string instance; if lenght is greater than this string instance, return the string.</returns>
        public static string Right(this string value, int length)
        {
            return value != null && value.Length > length ? value.Substring(value.Length - length) : value;
        }

        /// <summary>
        /// Returns characters from left of specified length
        /// </summary>
        /// <param name="value"></param>
        /// <param name="length">Max number of characters to return</param>
        /// <returns>Returns the first "lenght" characters from this string instance; if lenght is greater than this string instance, return the string.</returns>
        public static string Left(this string value, int length)
        {
            return value != null && value.Length > length ? value.Substring(0, length) : value;
        }

        /// <summary>
        /// Formats the string according to the specified mask
        /// </summary>
        /// <param name="value"></param>
        /// <param name="mask">The mask for formatting. Like "A##-##-T-###Z"</param>
        /// <returns>The formatted string</returns>
        public static string FormatWithMask(this string value, string mask)
        {
            if (String.IsNullOrEmpty(value)) return value;
            var output = string.Empty;
            var index = 0;
            foreach (var m in mask)
            {
                if (m == '#')
                {
                    if (index < value.Length)
                    {
                        output += value[index];
                        index++;
                    }
                }
                else
                    output += m;
            }
            return output;
        }

        /// <summary>
        /// Encryptes a string using the supplied key. Encoding is done using RSA encryption.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">The encription key.</param>
        /// <returns>A string representing a byte array separated by a minus sign.</returns>
        /// <exception cref="ArgumentException">Occurs when stringToEncrypt or key is null or empty.</exception>
        public static string Encrypt(this string value, string key)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("An empty string value cannot be encrypted.");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentException("Cannot encrypt using an empty key. Please supply an encryption key.");
            }

            CspParameters cspp = new CspParameters();
            cspp.KeyContainerName = key;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cspp);
            rsa.PersistKeyInCsp = true;

            byte[] bytes = rsa.Encrypt(System.Text.UTF8Encoding.UTF8.GetBytes(value), true);

            return BitConverter.ToString(bytes);
        }

        /// <summary>
        /// Decryptes a string using the supplied key. Decoding is done using RSA encryption.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted string or null if decryption failed.</returns>
        /// <exception cref="ArgumentException">Occurs when stringToDecrypt or key is null or empty.</exception>
        public static string Decrypt(this string value, string key)
        {
            string result = null;

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("An empty string value cannot be encrypted.");
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentException("Cannot decrypt using an empty key. Please supply a decryption key.");
            }

            try
            {
                CspParameters cspp = new CspParameters();
                cspp.KeyContainerName = key;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cspp);
                rsa.PersistKeyInCsp = true;

                string[] decryptArray = value.Split(new string[] { "-" }, StringSplitOptions.None);
                byte[] decryptByteArray = Array.ConvertAll<string, byte>(decryptArray, (s => Convert.ToByte(byte.Parse(s, System.Globalization.NumberStyles.HexNumber))));


                byte[] bytes = rsa.Decrypt(decryptByteArray, true);

                result = System.Text.UTF8Encoding.UTF8.GetString(bytes);

            }
            finally
            {
                // no need for further processing
            }

            return result;
        }

        /// <summary>
        /// Check if a string is a number
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Returns true if this string instance is numeric, otherwise false.</returns>
        public static bool IsNumeric(this string value)
        {
            return long.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.NumberFormatInfo.InvariantInfo, out _);
        }

        /// <summary>
        /// Supported hash algorithms
        /// </summary>
        public enum eHashType
        {
            HMAC, HMACMD5, HMACSHA1, HMACSHA256, HMACSHA384, HMACSHA512,
             MD5,  SHA1, SHA256, SHA384, SHA512
        }

        private static byte[] GetHash(string input, eHashType hash)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            switch (hash)
            {
                case eHashType.HMAC:
                    return HMAC.Create().ComputeHash(inputBytes);

                case eHashType.HMACMD5:
                    return HMACMD5.Create().ComputeHash(inputBytes);

                case eHashType.HMACSHA1:
                    return HMACSHA1.Create().ComputeHash(inputBytes);

                case eHashType.HMACSHA256:
                    return HMACSHA256.Create().ComputeHash(inputBytes);

                case eHashType.HMACSHA384:
                    return HMACSHA384.Create().ComputeHash(inputBytes);

                case eHashType.HMACSHA512:
                    return HMACSHA512.Create().ComputeHash(inputBytes);
                
                case eHashType.MD5:
                    return MD5.Create().ComputeHash(inputBytes);                

                case eHashType.SHA1:
                    return SHA1.Create().ComputeHash(inputBytes);

                case eHashType.SHA256:
                    return SHA256.Create().ComputeHash(inputBytes);

                case eHashType.SHA384:
                    return SHA384.Create().ComputeHash(inputBytes);

                case eHashType.SHA512:
                    return SHA512.Create().ComputeHash(inputBytes);

                default:
                    return inputBytes;
            }
        }

        /// <summary>
        /// Computes the hash of this string using a specified hash algorithm
        /// </summary>
        /// <param name="input"></param>
        /// <param name="hashType">The hash algorithm to use</param>
        /// <returns>The resulting hash</returns>
        public static string ComputeHash(this string value, eHashType hashType)
        {
            try
            {
                byte[] hash = GetHash(value, hashType);
                StringBuilder ret = new StringBuilder();

                for (int i = 0; i < hash.Length; i++)
                    ret.Append(hash[i].ToString("x2"));

                return ret.ToString();
            }
            catch(Exception ex)
            {
                throw new Exception($"An unhandled exception happened. {ex.ToString()}");
            }
        }
        /// <summary>
        /// Get the current file extension of this string.
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Return the extension of this string, without the leading dot.</returns>
        /// <exception cref="Exception">Occurs when string doesn't have any extension.</exception>
        public static string GetExtension(this string value)
        {
            if (!value.Contains('.'))
            {
                throw new Exception("This string doesn't contain any extension.");
            }
            var splitted = value.Split('.');
            return splitted.Last();
        }

        /// <summary>
        /// Get the current file extension of this string, if any. Otherwise return empty string.
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Return the extension of this string, without the leading dot.</returns>        
        public static string GetExtensionSafe(this string value)
        {
            if (!value.Contains('.'))
            {
                return "";
            }
            var splitted = value.Split('.');
            return splitted.Last();
        }
    }
}
