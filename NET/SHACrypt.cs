using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;

namespace gestioneLogin.engine;

class Crypt{
    internal KeyValuePair<string,string> EncryptSaltString(string sValue){
        byte[] byteSalt = new byte[16];
        string EncResult = string.Empty;
        string EncSalt = string.Empty;
        try
        {
            RandomNumberGenerator.Fill(byteSalt);
            EncResult = Convert.ToBase64String(
                //dotnet add package Microsoft.AspNetCore.Cryptography.KeyDerivation --version 7.0.12
                KeyDerivation.Pbkdf2(   
                    password: sValue,
                    salt: byteSalt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: 10000,
                    numBytesRequested: 16
                )
            );
            EncSalt = Convert.ToBase64String(byteSalt);
            System.Console.WriteLine(EncSalt);
            Console.ReadKey();
        }
        catch (System.Exception)
        {
            throw;
        }
        return new KeyValuePair<string, string>(EncSalt, EncResult);
    }

    internal bool VerifyPassword(string enteredPassword, KeyValuePair<string, string> hashedSalt)
    {
        byte[] salt = Convert.FromBase64String(hashedSalt.Key);
        byte[] hash = Convert.FromBase64String(hashedSalt.Value);

        byte[] newHash = KeyDerivation.Pbkdf2(
            password: enteredPassword,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 16
        );

        return newHash.SequenceEqual(hash);
    }

}