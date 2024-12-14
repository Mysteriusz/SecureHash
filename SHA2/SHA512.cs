﻿using System;

namespace SecureHash.SHA2
{
    public class SHA512 : IDisposable
    {
        private SHA512() { }

        public const int DigestSize = 512;
        public const int WordSize = 64;
        public const int BlockSize = 1024;

        public readonly ulong[] KValues =
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };
        public readonly ulong[] HValues =
        {
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
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
                uint[][] w = new uint[80][];

                for (int t = 0; t < 80; t++)
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

                for (int t = 0; t < 80; t++)
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
            int toPad = (896 - (bits.Length + 1) % BlockSize) % BlockSize;

            result.Add(1);
            result.AddRange(Enumerable.Repeat((uint)0, toPad));
            result.AddRange(GetBits(bits.Length, 128));

            return result.ToArray();
        }

        private uint[] E0(uint[] x) { return XOR(ROTR(x, 28), ROTR(x, 34), ROTR(x, 39)); }
        private uint[] E1(uint[] x) { return XOR(ROTR(x, 14), ROTR(x, 18), ROTR(x, 41)); }
        private uint[] S0(uint[] x) { return XOR(ROTR(x, 1), ROTR(x, 8), SHR(x, 7)); }
        private uint[] S1(uint[] x) { return XOR(ROTR(x, 19), ROTR(x, 61), SHR(x, 6)); }

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
        public static SHA512 Create()
        {
            return new SHA512();
        }
    }
}
