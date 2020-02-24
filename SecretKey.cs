using System;

namespace TransferUtilities
{
    internal class SecretKey
    {
        public byte[] Value { get; set; }
        public DateTime Creation { get; set; }
        public DateTime? Valid { get; set; }
        public string Owner { get; set; }
        public string Version { get; set; }
    }
}
