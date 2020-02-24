using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Text;
using System.IO;
using System;

namespace TransferUtilities
{
    public class Secret : IDisposable
    {
        private readonly byte[] defaults = new byte[16] { /* ... */ };
        private const string certificate = "=certificate";
        private const string fileExtencion = "key";

        private AesManaged Manager { get; }

        ICryptoTransform _encryptor, _decryptor;

        private ICryptoTransform Encryptor
        {
            get { return _encryptor ?? ( _encryptor = Manager.CreateEncryptor()); }
        }
        private ICryptoTransform Decryptor
        {
            get { return _decryptor ?? (_decryptor = Manager.CreateDecryptor()); }
        }

        public Secret(string key, byte[] vector = null)
        {
            if (string.IsNullOrWhiteSpace(key) || key.Length != 32)
                throw new ArgumentException("La longitud de la llave debe ser de 32 digitos");

            if (vector != null && vector.Length != 16)
                throw new ArgumentException("La longitud del vector debe ser de 16 digitos");

            Manager = new AesManaged() 
            {
                Key = Encoding.UTF8.GetBytes(key),
                IV = vector ?? defaults
            };
        }
        public Secret(byte[] key, byte[] vector = null)
        {
            if (key != null && key.Length != 32)
                throw new ArgumentException("La longitud de la llave debe ser de 32 digitos");

            if (vector != null && vector.Length != 16)
                throw new ArgumentException("La longitud del vector debe ser de 16 digitos");

            Manager = new AesManaged() 
            {
                Key = key,
                IV = vector ?? defaults
            };
        }
        public Secret()
        {
            Manager = new AesManaged();
        }

        public byte[] Encrypt(in string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                throw new ArgumentNullException(nameof(text));

            MemoryStream memory = null;
            CryptoStream crypto = null;
            byte[] result = null;

            try
            {
                memory = new MemoryStream();
                crypto = new CryptoStream(memory, Encryptor, CryptoStreamMode.Write);

                using (var writer = new StreamWriter(crypto))
                    writer.Write(text);

                result = memory.ToArray();
            }
            catch (Exception exception)
            {
                throw exception;
            }
            finally
            {
                crypto?.Dispose();
                memory?.Dispose();
            }

            return result;
        }
        public string Decrypt(in byte[] content)
        {
            if (content == null || content.Length == 0)
                throw new ArgumentNullException(nameof(content));

            CryptoStream crypton = null;
            MemoryStream memory = null;
            StreamReader reader = null;
            string result = null;

            try
            {
                memory = new MemoryStream(content);
                crypton = new CryptoStream(memory, Decryptor, CryptoStreamMode.Read);
                reader = new StreamReader(crypton);
                result = reader.ReadToEnd();
            }
            catch (Exception exception)
            {
                throw exception; 
            }
            finally
            {
                reader?.Dispose();
                crypton?.Dispose();
                memory?.Dispose();
            }

            return result;
        }

        public static void GenerateKeyFile(string fileName, string filePath, string key = null)
        {
            #region Validations
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentNullException(nameof(fileName));

            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!string.IsNullOrWhiteSpace(key) && key.Length != 32)
                throw new ArgumentException("La longitud de la llave debe ser de 32 digitos");
            #endregion

            string path = $"{ filePath }/{ fileName }.{ fileExtencion }";
            string serialization;
            byte[] fileContent;

            var secretKey = new SecretKey()
            {
                Creation = DateTime.Now,
                Version = "1.0"
            };

            #region Set Key Value
            try
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    using (var manager = new AesManaged())
                        secretKey.Value = manager.Key;
                }
                else
                {
                    secretKey.Value = Encoding.UTF8.GetBytes(key);
                }
            }
            catch (Exception exception)
            {
                throw new Exception("Set Key Value Exception", exception);
            }
            #endregion

            #region Serialize Data
            try
            {
                serialization = JsonConvert.SerializeObject(secretKey);
            }
            catch (Exception exception)
            {
                throw new Exception("Serialize Data Exception", exception);
            }
            #endregion

            #region Encrypt Data
            try
            {
                using (var lockSecret = new Secret(certificate))
                {
                    fileContent = lockSecret.Encrypt(serialization);
                }
            }
            catch (Exception exception)
            {
                throw new Exception("Encrypt Data Exception", exception);
            }
            #endregion

            #region Create File
            try
            {
                File.WriteAllBytes(path, fileContent);
                File.SetAttributes(path, FileAttributes.ReadOnly);
            }
            catch (Exception exception)
            {
                throw new Exception("Create File Exception", exception);
            }
            #endregion
        }
        public static Secret ReadKeyFile(string filePath)
        {
            #region Validations
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));
            #endregion

            Secret secret, unlock = null;
            string serialization;
            SecretKey secretKey;
            byte[] fileContent;

            #region Read File Data
            try
            {
                fileContent = File.ReadAllBytes(filePath);
            }
            catch (Exception exception)
            {
                throw new Exception(" Read File Data Exception", exception);
            }
            #endregion

            #region Decrypt Data
            try
            {
                unlock = new Secret(certificate);
                serialization = unlock.Decrypt(fileContent);
            }
            catch (Exception exception)
            {
                throw new Exception("Decrypt Data Exception", exception);
            }
            finally
            {
                unlock?.Dispose();
            }
            #endregion

            #region Deserialize Data
            try
            {
                secretKey = JsonConvert.DeserializeObject<SecretKey>(serialization);
            }
            catch (Exception exception)
            {
                throw new Exception("Deserialize Data Exception", exception);
            }
            #endregion

            if (secretKey.Valid.HasValue && secretKey.Valid.Value < DateTime.Now)
                throw new UnauthorizedAccessException("Validation Expired");

            #region Get Key Value
            try
            {
                secret = new Secret(secretKey.Value);
            }
            catch (Exception exception)
            {
                throw new Exception("Get Key Value Exception", exception);
            }
            #endregion

            return secret;
        }

        public void Dispose()
        {
            Manager.Dispose();
        }
    }
}
