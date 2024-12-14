using System;

namespace SecureHash.SHA2
{
    public class SHA256 : IDisposable
    {
        private SHA256() { }

        public const int DigestSize = 256;
        public const int WordSize = 32;
        public const int BlockSize = 512;

        public readonly uint[] KValues =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        public readonly uint[] HValues =
        {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
        };

        // Computing
        public uint[] ComputeHashBits(byte[] bytes)
        {
            uint[] padded = Pad(GetBits(bytes));
            uint[][] splited = Split(padded, BlockSize);
            uint[] digest = MessageDigest(splited);

            return digest;
        }
        public byte[] ComputeHashBytes(byte[] bytes)
        {
            uint[] padded = Pad(GetBits(bytes));
            uint[][] splited = Split(padded, BlockSize);
            uint[] digest = MessageDigest(splited);

            byte[] result = ToBytes(digest);

            return result;
        }
        public string ComputeHashString(byte[] bytes)
        {
            uint[] padded = Pad(GetBits(bytes));
            uint[][] splited = Split(padded, BlockSize);
            uint[] digest = MessageDigest(splited);

            byte[] result = ToBytes(digest);

            return BitConverter.ToString(result).Replace("-", "").ToLower();
        }

        // Core Methods
        private uint[] MessageDigest(uint[][] blocks)
        {
            uint[] H0 = H(0);
            uint[] H1 = H(1);
            uint[] H2 = H(2);
            uint[] H3 = H(3);
            uint[] H4 = H(4);
            uint[] H5 = H(5);
            uint[] H6 = H(6);
            uint[] H7 = H(7);

            for (int i = 0; i < blocks.Length; i++)
            {
                uint[][] splited = Split(blocks[i], WordSize);
                uint[][] w = new uint[64][];

                for (int t = 0; t < 64; t++)
                {
                    if (t < 16)
                    {
                        w[t] = splited[t];
                        continue;
                    }

                    uint[] l = MOD2(S1(w[t - 2]), w[t - 7]);
                    uint[] r = MOD2(S0(w[t - 15]), w[t - 16]);

                    w[t] = MOD2(l, r);
                }

                uint[] a = H0;
                uint[] b = H1;
                uint[] c = H2;
                uint[] d = H3;
                uint[] e = H4;
                uint[] f = H5;
                uint[] g = H6;
                uint[] h = H7;

                for (int t = 0; t < 64; t++)
                {
                    uint[] kw = MOD2(K(t), w[t]);
                    uint[] chk = MOD2(CH(e, f, g), kw);
                    uint[] ech = MOD2(E1(e), chk);

                    uint[] T1 = MOD2(h, ech);
                    uint[] T2 = MOD2(E0(a), MAJ(a, b, c));

                    h = g;
                    g = f;
                    f = e;
                    e = MOD2(d, T1);
                    d = c;
                    c = b;
                    b = a;
                    a = MOD2(T1, T2);
                }

                H0 = MOD2(a, H0);
                H1 = MOD2(b, H1);
                H2 = MOD2(c, H2);
                H3 = MOD2(d, H3);
                H4 = MOD2(e, H4);
                H5 = MOD2(f, H5);
                H6 = MOD2(g, H6);
                H7 = MOD2(h, H7);
            }

            return H0.Concat(H1).Concat(H2).Concat(H3).Concat(H4).Concat(H5).Concat(H6).Concat(H7).ToArray();
        }
        private uint[] Pad(uint[] bits)
        {
            List<uint> result = new(bits);
            int toPad = (448 - (bits.Length + 1) % BlockSize) % BlockSize;

            result.Add(1);
            result.AddRange(Enumerable.Repeat((uint)0, toPad));
            result.AddRange(GetBits(bits.Length, 64));

            return result.ToArray();
        }

        private uint[] E0(uint[] x) { return XOR(ROTR(x, 2), ROTR(x, 13), ROTR(x, 22)); }
        private uint[] E1(uint[] x) { return XOR(ROTR(x, 6), ROTR(x, 11), ROTR(x, 25)); }
        private uint[] S0(uint[] x) { return XOR(ROTR(x, 7), ROTR(x, 18), SHR(x, 3)); }
        private uint[] S1(uint[] x) { return XOR(ROTR(x, 17), ROTR(x, 19), SHR(x, 10)); }

        private uint[] K(int index) { return GetBits(KValues[index]); }
        private uint[] H(int index) { return GetBits(HValues[index]); }

        private uint[] MOD2(uint[] x, uint[] y)
        {
            if (x.Length != y.Length)
                throw new ArgumentException("Arrays must be of the same length");

            uint[] result = new uint[x.Length];
            uint carry = 0;

            for (int i = x.Length - 1; i >= 0; i--)
            {
                uint sum = x[i] + y[i] + carry;
                result[i] = sum % 2;
                carry = sum / 2;
            }

            return result;
        }
        private uint[] ROTR(uint[] x, int s)
        {
            int n = x.Length;
            uint[] result = new uint[x.Length];

            for (int i = 0; i < n; i++)
            {
                int newIndex = ((i + s) + n) % n;
                result[newIndex] = x[i];
            }

            return result;
        }
        private uint[] SHR(uint[] x, int s)
        {
            int n = x.Length;

            uint[] result = ROTR(x, s).Skip(s).ToArray();
            uint[] empty = new uint[s];

            return empty.Concat(result).ToArray();
        }

        private uint[] CH(uint[] x, uint[] y, uint[] z)
        {
            uint[] result = new uint[WordSize];

            for (int i = 0; i < x.Length; i++)
                result[i] = (x[i] & y[i]) ^ (~x[i] & z[i]);

            return result;
        }
        private uint[] MAJ(uint[] x, uint[] y, uint[] z)
        {
            uint[] result = new uint[WordSize];

            for (int i = 0; i < x.Length; i++)
                result[i] = (x[i] & y[i]) ^ (x[i] & z[i]) ^ (y[i] & z[i]);

            return result;
        }

        // Helper Methods
        private uint[][] Split(uint[] bits, int s)
        {
            if (bits.Length % s != 0) throw new ArgumentException("Cannot split");

            int splitCount = bits.Length / s;
            uint[][] result = new uint[splitCount][];

            for (int i = 0; i < splitCount; i++)
            {
                result[i] = new uint[s];
                Array.Copy(bits, i * s, result[i], 0, s);
            }

            return result;
        }

        private uint[] XOR(params uint[][] arrays)
        {
            uint[] result = new uint[arrays[0].Length];

            foreach (uint[] array in arrays)
                for (int i = 0; i < array.Length; i++)
                    result[i] ^= array[i];

            return result;
        }

        private uint[] GetBits(ulong x)
        {
            uint[] result = new uint[WordSize];

            for (int i = 0; i < WordSize; i++)
                result[i] = (uint)(x >> (WordSize - 1 - i)) & 1;

            return result;
        }
        private uint[] GetBits(int x, int count)
        {
            uint[] result = new uint[count];

            for (int i = 0; i < count; i++)
            {
                result[count - 1 - i] = (uint)(x & 1);
                x >>= 1;
            }

            return result;
        }
        private uint[] GetBits(byte[] x)
        {
            uint[] result = new uint[x.Length * 8];

            int bIndex = 0;

            for (int i = 0; i < x.Length; i++)
                for (int b = 0; b < 8; b++)
                    result[bIndex++] = (uint)((x[i] >> (7 - b)) & 1);

            return result;
        }

        private byte[] ToBytes(uint[] bits)
        {
            int byteCount = bits.Length / 8;
            byte[] result = new byte[byteCount];

            for (int i = 0; i < bits.Length; i++)
            {
                int byteIndex = i / 8;
                int bitIndex = 7 - (i % 8);

                if (bits[i] == 1)
                    result[byteIndex] |= (byte)(1 << bitIndex);
            }

            return result;
        }

        // Disposing
        private bool _disposed;
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {

            }

            _disposed = true;
        }
        public static SHA256 Create()
        {
            return new SHA256();
        }
    }
}
